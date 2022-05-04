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
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/csaf-poc/csaf_distribution/csaf"
	"github.com/csaf-poc/csaf_distribution/util"
)

func (w *worker) handleROLIE(
	rolie interface{},
	process func(*csaf.Feed, []string) error,
) error {
	base, err := url.Parse(w.loc)
	if err != nil {
		return err
	}
	var feeds [][]csaf.Feed
	if err := util.ReMarshalJSON(&feeds, rolie); err != nil {
		return err
	}
	log.Printf("Found %d ROLIE feed(s).\n", len(feeds))

	for _, fs := range feeds {
		for i := range fs {
			feed := &fs[i]
			if feed.URL == nil {
				continue
			}
			up, err := url.Parse(string(*feed.URL))
			if err != nil {
				log.Printf("Invalid URL %s in feed: %v.", *feed.URL, err)
				continue
			}
			feedURL := base.ResolveReference(up).String()
			log.Printf("Feed URL: %s\n", feedURL)

			fb, err := util.BaseURL(feedURL)
			if err != nil {
				log.Printf("error: Invalid feed base URL '%s': %v\n", fb, err)
				continue
			}
			feedBaseURL, err := url.Parse(fb)
			if err != nil {
				log.Printf("error: Cannot parse feed base URL '%s': %v\n", fb, err)
				continue
			}

			res, err := w.client.Get(feedURL)
			if err != nil {
				log.Printf("error: Cannot get feed '%s'\n", err)
				continue
			}
			if res.StatusCode != http.StatusOK {
				log.Printf("error: Fetching %s failed. Status code %d (%s)",
					feedURL, res.StatusCode, res.Status)
				continue
			}
			rfeed, err := func() (*csaf.ROLIEFeed, error) {
				defer res.Body.Close()
				return csaf.LoadROLIEFeed(res.Body)
			}()
			if err != nil {
				log.Printf("Loading ROLIE feed failed: %v.", err)
				continue
			}
			files := resolveURLs(rfeed.Files(), feedBaseURL)
			if err := process(feed, files); err != nil {
				return err
			}
		}
	}
	return nil
}

// mirrorAllowed checks if mirroring is allowed.
func (w *worker) mirrorAllowed() bool {
	if a, err := w.expr.Eval(
		"$.mirror_on_CSAF_aggregators",
		w.metadataProvider,
	); err == nil {
		if ma, ok := a.(bool); ok {
			return ma
		}
	}
	return true
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
	//if false && !w.mirrorAllowed() {
	if !w.mirrorAllowed() {
		return nil, fmt.Errorf(
			"no mirroring of '%s' allowed", w.provider.Name)
	}

	// Collecting the summaries of the advisories.
	w.summaries = make(map[string][]summary)

	// Check if we have ROLIE feeds.
	rolie, err := w.expr.Eval(
		"$.distributions[*].rolie.feeds", w.metadataProvider)
	if err != nil {
		log.Printf("rolie check failed: %v\n", err)
		return nil, err
	}

	fs, hasRolie := rolie.([]interface{})
	hasRolie = hasRolie && len(fs) > 0

	if hasRolie {
		if err := w.handleROLIE(rolie, w.mirrorFiles); err != nil {
			return nil, err
		}
	} else {
		// No rolie feeds
		// TODO: Implement me!
	}

	if err := w.writeIndices(); err != nil {
		return nil, err
	}

	if err := w.doMirrorTransaction(); err != nil {
		return nil, err
	}

	return w.createAggregatorProvider()
}

// createAggregatorProvider the "metadata" section in the "csaf_providers" of
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
		Mirrors: []csaf.ProviderURL{csaf.ProviderURL(w.loc)},
	}, nil
}

// doMirrorTransaction performs an atomic directory swap.
func (w *worker) doMirrorTransaction() error {

	webTarget := filepath.Join(
		w.cfg.Web, ".well-known", "csaf-aggregator", w.provider.Name)

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
	target := filepath.Join(w.cfg.Folder, w.provider.Name)
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
		key, err := w.cfg.cryptoKey()
		if err != nil {
			return "", err
		}
		if key == nil {
			return "", nil
		}
		if pp := w.cfg.Passphrase; pp != nil {
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
	return sig.GetArmored()
}

func (w *worker) mirrorFiles(feed *csaf.Feed, files []string) error {
	label := "unknown"
	if feed.TLPLabel != nil {
		label = strings.ToLower(string(*feed.TLPLabel))
	}

	summaries := w.summaries[label]

	dir, err := w.createDir()
	if err != nil {
		return err
	}

	var content bytes.Buffer

	yearDirs := make(map[int]string)

	for _, file := range files {
		u, err := url.Parse(file)
		if err != nil {
			log.Printf("error: %s\n", err)
			continue
		}
		filename := util.CleanFileName(filepath.Base(u.Path))

		var advisory interface{}

		s256 := sha256.New()
		s512 := sha512.New()
		content.Reset()
		hasher := io.MultiWriter(s256, s512, &content)

		download := func(r io.Reader) error {
			tee := io.TeeReader(r, hasher)
			return json.NewDecoder(tee).Decode(&advisory)
		}

		if err := downloadJSON(w.client, file, download); err != nil {
			log.Printf("error: %v\n", err)
			continue
		}

		errors, err := csaf.ValidateCSAF(advisory)
		if err != nil {
			log.Printf("error: %s: %v", file, err)
			continue
		}
		if len(errors) > 0 {
			log.Printf("CSAF file %s has %d validation errors.",
				file, len(errors))
			continue
		}

		sum, err := csaf.NewAdvisorySummary(w.expr, advisory)
		if err != nil {
			log.Printf("error: %s: %v\n", file, err)
			continue
		}
		summaries = append(summaries, summary{
			filename: filename,
			summary:  sum,
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
		sigURL := file + ".asc"
		sig, err := w.downloadSignature(sigURL)

		if err != nil {
			if err != errNotFound {
				log.Printf("error: %s: %v\n", sigURL, err)
			}
			// Sign it our self.
			if sig, err = w.sign(data); err != nil {
				return err
			}
		}

		if sig != "" {
			if err := os.WriteFile(fname+".asc", []byte(sig), 0644); err != nil {
				return err
			}
		}
	}
	w.summaries[label] = summaries

	return nil
}
