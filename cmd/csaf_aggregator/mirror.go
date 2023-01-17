// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/armor"
	"github.com/ProtonMail/gopenpgp/v2/constants"
	"github.com/ProtonMail/gopenpgp/v2/crypto"

	"github.com/csaf-poc/csaf_distribution/csaf"
	"github.com/csaf-poc/csaf_distribution/util"
)

// mirrorAllowed checks if mirroring is allowed.
func (w *worker) mirrorAllowed() bool {
	var b bool
	return w.expr.Extract(
		`$.mirror_on_CSAF_aggregators`,
		util.BoolMatcher(&b), false, w.metadataProvider) == nil && b
}

func (w *worker) mirror() (*csaf.AggregatorCSAFProvider, error) {
	result, err := w.mirrorInternal()
	if err != nil && w.dir != "" {
		// If something goes wrong remove the debris.
		if err := os.RemoveAll(w.dir); err != nil {
			log.Printf("error: %v\n", err)
		}
	}
	return result, err
}

func (w *worker) mirrorInternal() (*csaf.AggregatorCSAFProvider, error) {

	// Check if we are allowed to mirror this domain.
	if !w.mirrorAllowed() {
		return nil, fmt.Errorf(
			"no mirroring of '%s' allowed", w.provider.Name)
	}

	// Collecting the summaries of the advisories.
	w.summaries = make(map[string][]summary)

	// Collecting the categories per label.
	w.categories = make(map[string]map[string]bool)

	base, err := url.Parse(w.loc)
	if err != nil {
		return nil, err
	}

	afp := csaf.NewAdvisoryFileProcessor(
		w.client,
		w.expr,
		w.metadataProvider,
		base,
		nil)

	if err := afp.Process(w.mirrorFiles); err != nil {
		return nil, err
	}

	if err := w.writeIndices(); err != nil {
		return nil, err
	}

	if err := w.doMirrorTransaction(); err != nil {
		return nil, err
	}

	if err := w.writeProviderMetadata(); err != nil {
		return nil, err
	}

	acp, err := w.createAggregatorProvider()

	if err != nil {
		return nil, err
	}

	// Add us as a mirror.
	mirrorURL := csaf.ProviderURL(
		fmt.Sprintf("%s/.well-known/csaf-aggregator/%s/provider-metadata.json",
			w.processor.cfg.Domain, w.provider.Name))

	acp.Mirrors = []csaf.ProviderURL{
		mirrorURL,
	}

	return acp, err
}

func (w *worker) labelsFromSummaries() []csaf.TLPLabel {
	labels := make([]csaf.TLPLabel, 0, len(w.summaries))
	for label := range w.summaries {
		labels = append(labels, csaf.TLPLabel(strings.ToUpper(label)))
	}
	sort.Slice(labels, func(i, j int) bool { return labels[i] < labels[j] })
	return labels
}

// writeProviderMetadata writes a local provider metadata for a mirror.
func (w *worker) writeProviderMetadata() error {

	fname := filepath.Join(w.dir, "provider-metadata.json")

	pm := csaf.NewProviderMetadataPrefix(
		w.processor.cfg.Domain+"/.well-known/csaf-aggregator/"+w.provider.Name,
		w.labelsFromSummaries())

	// Fill in directory URLs if needed.
	if w.provider.writeIndices(w.processor.cfg) {
		labels := make([]string, 0, len(w.summaries))
		for label := range w.summaries {
			labels = append(labels, label)
		}
		sort.Strings(labels)
		prefix := w.processor.cfg.Domain + "/.well-known/csaf-aggregator/" + w.provider.Name + "/"
		for _, label := range labels {
			pm.AddDirectoryDistribution(prefix + label)
		}
	}

	// Figure out the role
	var role csaf.MetadataRole

	if strings.HasPrefix(w.provider.Domain, "https://") {
		role = csaf.MetadataRolePublisher
	} else {
		role = csaf.MetadataRoleProvider
	}

	pm.Role = &role

	pm.Publisher = new(csaf.Publisher)

	var lastUpdate time.Time

	if err := w.expr.Match([]util.PathEvalMatcher{
		{Expr: `$.publisher`, Action: util.ReMarshalMatcher(pm.Publisher)},
		{Expr: `$.last_updated`, Action: util.TimeMatcher(&lastUpdate, time.RFC3339)},
		{Expr: `$.public_openpgp_keys`, Action: util.ReMarshalMatcher(&pm.PGPKeys)},
	}, w.metadataProvider); err != nil {
		// only log the errors
		log.Printf("extracting data from orignal provider failed: %v\n", err)
	}

	// We are mirroring the remote public keys, too.
	if err := w.mirrorPGPKeys(pm); err != nil {
		return err
	}

	la := csaf.TimeStamp(lastUpdate)
	pm.LastUpdated = &la

	return util.WriteToFile(fname, pm)
}

// mirrorPGPKeys creates a local openpgp folder and downloads the referenced
// OpenPGP keys into it. The own key is also inserted.
func (w *worker) mirrorPGPKeys(pm *csaf.ProviderMetadata) error {
	openPGPFolder := filepath.Join(w.dir, "openpgp")
	if err := os.MkdirAll(openPGPFolder, 0755); err != nil {
		return err
	}

	localKeyURL := func(fingerprint string) string {
		return fmt.Sprintf("%s/.well-known/csaf-aggregator/%s/openpgp/%s.asc",
			w.processor.cfg.Domain, w.provider.Name, fingerprint)
	}

	for i := range pm.PGPKeys {
		pgpKey := &pm.PGPKeys[i]
		if pgpKey.URL == nil {
			log.Printf("ignoring PGP key without URL: %s\n", pgpKey.Fingerprint)
			continue
		}
		if _, err := hex.DecodeString(string(pgpKey.Fingerprint)); err != nil {
			log.Printf("ignoring PGP with invalid fingerprint: %s\n", *pgpKey.URL)
			continue
		}

		// Fetch remote key.
		res, err := w.client.Get(*pgpKey.URL)
		if err != nil {
			os.RemoveAll(openPGPFolder)
			return err
		}

		if res.StatusCode != http.StatusOK {
			os.RemoveAll(openPGPFolder)
			return fmt.Errorf("cannot fetch PGP key %s: %s (%d)",
				*pgpKey.URL, res.Status, res.StatusCode)
		}

		fingerprint := strings.ToUpper(string(pgpKey.Fingerprint))

		localFile := filepath.Join(openPGPFolder, fingerprint+".asc")

		// Download the remote key into our new folder.
		if err := func() error {
			defer res.Body.Close()
			out, err := os.Create(localFile)
			if err != nil {
				return err
			}
			_, err1 := io.Copy(out, res.Body)
			err2 := out.Close()
			if err1 != nil {
				return err1
			}
			return err2
		}(); err != nil {
			os.RemoveAll(openPGPFolder)
			return err
		}

		// replace the URL
		url := localKeyURL(fingerprint)
		pgpKey.URL = &url
	}

	// If we have public key configured copy it into the new folder

	if w.processor.cfg.OpenPGPPublicKey == "" {
		return nil
	}

	// Load the key for the fingerprint.
	data, err := os.ReadFile(w.processor.cfg.OpenPGPPublicKey)
	if err != nil {
		os.RemoveAll(openPGPFolder)
		return err
	}

	key, err := crypto.NewKeyFromArmoredReader(bytes.NewReader(data))
	if err != nil {
		os.RemoveAll(openPGPFolder)
		return err
	}

	fingerprint := strings.ToUpper(key.GetFingerprint())

	localFile := filepath.Join(openPGPFolder, fingerprint+".asc")

	// Write copy back into new folder.
	if err := os.WriteFile(localFile, data, 0644); err != nil {
		os.RemoveAll(openPGPFolder)
		return err
	}

	// Add to the URLs.
	pm.SetPGP(fingerprint, localKeyURL(fingerprint))

	return nil
}

// createAggregatorProvider fills the "metadata" section in the "csaf_providers" of
// the aggregator document.
func (w *worker) createAggregatorProvider() (*csaf.AggregatorCSAFProvider, error) {
	const (
		lastUpdatedExpr = `$.last_updated`
		publisherExpr   = `$.publisher`
		roleExpr        = `$.role`
		urlExpr         = `$.canonical_url`
	)

	var (
		lastUpdatedT time.Time
		pub          csaf.Publisher
		roleS        string
		urlS         string
	)

	if err := w.expr.Match([]util.PathEvalMatcher{
		{Expr: lastUpdatedExpr, Action: util.TimeMatcher(&lastUpdatedT, time.RFC3339)},
		{Expr: publisherExpr, Action: util.ReMarshalMatcher(&pub)},
		{Expr: roleExpr, Action: util.StringMatcher(&roleS)},
		{Expr: urlExpr, Action: util.StringMatcher(&urlS)},
	}, w.metadataProvider); err != nil {
		return nil, err
	}

	var (
		lastUpdated = csaf.TimeStamp(lastUpdatedT)
		role        = csaf.MetadataRole(roleS)
		url         = csaf.ProviderURL(urlS)
	)

	return &csaf.AggregatorCSAFProvider{
		Metadata: &csaf.AggregatorCSAFProviderMetadata{
			LastUpdated: &lastUpdated,
			Publisher:   &pub,
			Role:        &role,
			URL:         &url,
		},
	}, nil
}

// doMirrorTransaction performs an atomic directory swap.
func (w *worker) doMirrorTransaction() error {

	webTarget := filepath.Join(
		w.processor.cfg.Web, ".well-known", "csaf-aggregator", w.provider.Name)

	var oldWeb string

	// Resolve old to be removed later
	if _, err := os.Stat(webTarget); err != nil {
		if !os.IsNotExist(err) {
			os.RemoveAll(w.dir)
			return err
		}
	} else {
		if oldWeb, err = filepath.EvalSymlinks(webTarget); err != nil {
			os.RemoveAll(w.dir)
			return err
		}
	}

	// Check if there is a sysmlink already.
	target := filepath.Join(w.processor.cfg.Folder, w.provider.Name)
	log.Printf("target: '%s'\n", target)

	exists, err := util.PathExists(target)
	if err != nil {
		os.RemoveAll(w.dir)
		return err
	}

	if exists {
		if err := os.RemoveAll(target); err != nil {
			os.RemoveAll(w.dir)
			return err
		}
	}

	log.Printf("sym link: %s -> %s\n", w.dir, target)

	// Create a new symlink
	if err := os.Symlink(w.dir, target); err != nil {
		os.RemoveAll(w.dir)
		return err
	}

	// Move the symlink
	log.Printf("Move: %s -> %s\n", target, webTarget)
	if err := os.Rename(target, webTarget); err != nil {
		os.RemoveAll(w.dir)
		return err
	}

	// Finally remove the old folder.
	if oldWeb != "" {
		return os.RemoveAll(oldWeb)
	}
	return nil
}

// downloadSignature downloads an OpenPGP signature from a given url.
func (w *worker) downloadSignature(path string) (string, error) {
	res, err := w.client.Get(path)
	if err != nil {
		return "", err
	}
	if res.StatusCode != http.StatusOK {
		return "", errNotFound
	}
	data, err := func() ([]byte, error) {
		defer res.Body.Close()
		return io.ReadAll(res.Body)
	}()
	if err != nil {
		return "", err
	}
	result := string(data)
	if _, err := crypto.NewPGPMessageFromArmored(result); err != nil {
		return "", err
	}
	return result, nil
}

// sign signs the given data with the configured key.
func (w *worker) sign(data []byte) (string, error) {
	if w.signRing == nil {
		key, err := w.processor.cfg.privateOpenPGPKey()
		if err != nil {
			return "", err
		}
		if key == nil {
			return "", nil
		}
		if pp := w.processor.cfg.Passphrase; pp != nil {
			if key, err = key.Unlock([]byte(*pp)); err != nil {
				return "", err
			}
		}
		if w.signRing, err = crypto.NewKeyRing(key); err != nil {
			return "", err
		}
	}
	sig, err := w.signRing.SignDetached(crypto.NewPlainMessage(data))
	if err != nil {
		return "", err
	}
	return armor.ArmorWithTypeAndCustomHeaders(
		sig.Data, constants.PGPSignatureHeader, "", "")
}

func (w *worker) extractCategories(label string, advisory any) error {

	// use provider or global categories
	var categories []string
	if w.provider.Categories != nil {
		categories = *w.provider.Categories
	} else if w.processor.cfg.Categories != nil {
		categories = *w.processor.cfg.Categories
	}

	// Nothing to do.
	if len(categories) == 0 {
		return nil
	}

	cats := w.categories[label]
	if cats == nil {
		cats = make(map[string]bool)
		w.categories[label] = cats
	}

	var result string
	matcher := util.StringMatcher(&result)

	const exprPrefix = "expr:"

	for _, cat := range categories {
		if strings.HasPrefix(cat, exprPrefix) {
			expr := cat[len(exprPrefix):]
			if err := w.expr.Extract(expr, matcher, true, advisory); err != nil {
				return err
			}
			cats[result] = true
		} else { // Normal
			cats[cat] = true
		}
	}

	return nil
}

func (w *worker) mirrorFiles(tlpLabel csaf.TLPLabel, files []csaf.AdvisoryFile) error {
	label := strings.ToLower(string(tlpLabel))

	summaries := w.summaries[label]

	dir, err := w.createDir()
	if err != nil {
		return err
	}

	var content bytes.Buffer

	yearDirs := make(map[int]string)

	for _, file := range files {
		u, err := url.Parse(file.URL())
		if err != nil {
			log.Printf("error: %s\n", err)
			continue
		}

		// Ignore not confirming filenames.
		filename := filepath.Base(u.Path)
		if !util.ConfirmingFileName(filename) {
			log.Printf("Not confirming filename %q. Ignoring.\n", filename)
			continue
		}

		var advisory any

		s256 := sha256.New()
		s512 := sha512.New()
		content.Reset()
		hasher := io.MultiWriter(s256, s512, &content)

		download := func(r io.Reader) error {
			tee := io.TeeReader(r, hasher)
			return json.NewDecoder(tee).Decode(&advisory)
		}

		if err := downloadJSON(w.client, file.URL(), download); err != nil {
			log.Printf("error: %v\n", err)
			continue
		}

		// Check against CSAF schema.
		errors, err := csaf.ValidateCSAF(advisory)
		if err != nil {
			log.Printf("error: %s: %v", file, err)
			continue
		}
		if len(errors) > 0 {
			log.Printf("CSAF file %s has %d validation errors.\n",
				file, len(errors))
			continue
		}

		// Check against remote validator.
		if rmv := w.processor.remoteValidator; rmv != nil {
			valid, err := rmv.Validate(advisory)
			if err != nil {
				log.Printf("Calling remote validator failed: %s\n", err)
				continue
			}
			if !valid {
				log.Printf(
					"CSAF file %s does not validate remotely.\n", file)
				continue
			}
		}

		sum, err := csaf.NewAdvisorySummary(w.expr, advisory)
		if err != nil {
			log.Printf("error: %s: %v\n", file, err)
			continue
		}

		if err := w.extractCategories(label, advisory); err != nil {
			log.Printf("error: %s: %v\n", file, err)
			continue
		}

		summaries = append(summaries, summary{
			filename: filename,
			summary:  sum,
			url:      file.URL(),
		})

		year := sum.InitialReleaseDate.Year()

		yearDir := yearDirs[year]
		if yearDir == "" {
			yearDir = filepath.Join(dir, label, strconv.Itoa(year))
			if err := os.MkdirAll(yearDir, 0755); err != nil {
				return err
			}
			//log.Printf("created %s\n", yearDir)
			yearDirs[year] = yearDir
		}

		fname := filepath.Join(yearDir, filename)
		//log.Printf("write: %s\n", fname)
		data := content.Bytes()
		if err := writeFileHashes(
			fname, filename,
			data, s256.Sum(nil), s512.Sum(nil),
		); err != nil {
			return err
		}

		// Try to fetch signature file.
		sigURL := file.SignURL()
		ascFile := fname + ".asc"
		if err := w.downloadSignatureOrSign(sigURL, ascFile, data); err != nil {
			return err
		}
	}
	w.summaries[label] = summaries

	return nil
}

// downloadSignatureOrSign first tries to download a signature.
// If this fails it creates a signature itself with the configured key.
func (w *worker) downloadSignatureOrSign(url, fname string, data []byte) error {
	sig, err := w.downloadSignature(url)

	if err != nil {
		if err != errNotFound {
			log.Printf("error: %s: %v\n", url, err)
		}
		// Sign it our self.
		if sig, err = w.sign(data); err != nil {
			return err
		}
	}

	if sig != "" {
		err = os.WriteFile(fname, []byte(sig), 0644)
	}
	return err
}
