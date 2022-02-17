// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/PaesslerAG/gval"
	"github.com/PaesslerAG/jsonpath"
	"github.com/ProtonMail/gopenpgp/v2/crypto"

	"github.com/csaf-poc/csaf_distribution/csaf"
	"github.com/csaf-poc/csaf_distribution/util"
)

type processor struct {
	opts   *options
	client *http.Client

	redirects      map[string]string
	noneTLS        map[string]struct{}
	alreadyChecked map[string]whereType
	pmdURL         string
	pmd256         []byte
	pmd            interface{}
	keys           []*crypto.KeyRing

	badIntegrities       []string
	badPGPs              []string
	badSignatures        []string
	badProviderMetadatas []string
	badSecurities        []string
	badIndices           []string
	badChanges           []string
	badFolders           []string

	builder gval.Language
	exprs   map[string]gval.Evaluable
}

type reporter interface {
	report(*processor, *Domain)
}

var (
	// errContinue indicates that the current check should continue.
	errContinue = errors.New("continue")
	// errStop indicates that the current check should stop.
	errStop = errors.New("stop")
)

type whereType byte

const (
	rolieMask = whereType(1) << iota
	rolieIndexMask
	rolieChangesMask
	indexMask
	changesMask
)

func (wt whereType) String() string {
	switch wt {
	case rolieMask:
		return "ROLIE"
	case rolieIndexMask:
		return "index.txt [ROLIE]"
	case rolieChangesMask:
		return "changes.csv [ROLIE]"
	case indexMask:
		return "index.txt"
	case changesMask:
		return "changes.csv"
	default:
		var mixed []string
		for mask := rolieMask; mask <= changesMask; mask <<= 1 {
			if x := wt & mask; x == mask {
				mixed = append(mixed, x.String())
			}
		}
		return strings.Join(mixed, "|")
	}
}

func newProcessor(opts *options) *processor {
	return &processor{
		opts:           opts,
		alreadyChecked: map[string]whereType{},
		builder:        gval.Full(jsonpath.Language()),
		exprs:          map[string]gval.Evaluable{},
	}
}

func (p *processor) clean() {
	p.redirects = nil
	p.noneTLS = nil
	for k := range p.alreadyChecked {
		delete(p.alreadyChecked, k)
	}
	p.pmdURL = ""
	p.pmd256 = nil
	p.pmd = nil
	p.keys = nil

	p.badIntegrities = nil
	p.badPGPs = nil
	p.badSignatures = nil
	p.badProviderMetadatas = nil
	p.badSecurities = nil
	p.badIndices = nil
	p.badChanges = nil
}

func (p *processor) run(reporters []reporter, domains []string) (*Report, error) {

	var report Report

	for _, d := range domains {
		if err := p.checkDomain(d); err != nil {
			if err == errContinue || err == errStop {
				continue
			}
			return nil, err
		}
		domain := &Domain{Name: d}
		for _, r := range reporters {
			r.report(p, domain)
		}
		report.Domains = append(report.Domains, domain)
		p.clean()
	}

	return &report, nil
}

func (p *processor) checkDomain(domain string) error {

	// TODO: Implement me!
	for _, check := range []func(*processor, string) error{
		(*processor).checkProviderMetadata,
		(*processor).checkPGPKeys,
		(*processor).checkSecurity,
		(*processor).checkCSAFs,
		(*processor).checkMissing,
	} {
		if err := check(p, domain); err != nil && err != errContinue {
			if err == errStop {
				return nil
			}
			return err
		}
	}

	return nil
}

func (p *processor) jsonPath(expr string, doc interface{}) (interface{}, error) {
	if doc == nil {
		return nil, errors.New("no document to extract data from")
	}
	eval := p.exprs[expr]
	if eval == nil {
		var err error
		if eval, err = p.builder.NewEvaluable(expr); err != nil {
			return nil, err
		}
		p.exprs[expr] = eval
	}
	return eval(context.Background(), doc)
}

func (p *processor) checkTLS(u string) {
	if p.noneTLS == nil {
		p.noneTLS = map[string]struct{}{}
	}
	if x, err := url.Parse(u); err == nil && x.Scheme != "https" {
		p.noneTLS[u] = struct{}{}
	}
}

func (p *processor) markChecked(s string, mask whereType) bool {
	v, ok := p.alreadyChecked[s]
	p.alreadyChecked[s] = v | mask
	return ok
}

func (p *processor) checkRedirect(r *http.Request, via []*http.Request) error {

	var path strings.Builder
	for i, v := range via {
		if i > 0 {
			path.WriteString(", ")
		}
		path.WriteString(v.URL.String())
	}
	url := r.URL.String()
	p.checkTLS(url)
	if p.redirects == nil {
		p.redirects = map[string]string{}
	}
	p.redirects[url] = path.String()

	if len(via) > 10 {
		return errors.New("Too many redirections")
	}
	return nil
}

func (p *processor) httpClient() *http.Client {

	if p.client != nil {
		return p.client
	}

	p.client = &http.Client{
		CheckRedirect: p.checkRedirect,
	}

	if p.opts.Insecure {
		p.client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	}

	return p.client
}

func use(s *[]string) {
	if *s == nil {
		*s = []string{}
	}
}

func used(s []string) bool {
	return s != nil
}

func (p *processor) badIntegrity(format string, args ...interface{}) {
	p.badIntegrities = append(p.badIntegrities, fmt.Sprintf(format, args...))
}

func (p *processor) badSignature(format string, args ...interface{}) {
	p.badSignatures = append(p.badSignatures, fmt.Sprintf(format, args...))
}

func (p *processor) badProviderMetadata(format string, args ...interface{}) {
	p.badProviderMetadatas = append(p.badProviderMetadatas, fmt.Sprintf(format, args...))
}

func (p *processor) badPGP(format string, args ...interface{}) {
	p.badPGPs = append(p.badPGPs, fmt.Sprintf(format, args...))
}

func (p *processor) badSecurity(format string, args ...interface{}) {
	p.badSecurities = append(p.badSecurities, fmt.Sprintf(format, args...))
}

func (p *processor) badIndex(format string, args ...interface{}) {
	p.badIndices = append(p.badIndices, fmt.Sprintf(format, args...))
}

func (p *processor) badChange(format string, args ...interface{}) {
	p.badChanges = append(p.badChanges, fmt.Sprintf(format, args...))
}

func (p *processor) badFolder(format string, args ...interface{}) {
	p.badFolders = append(p.badFolders, fmt.Sprintf(format, args...))
}

var yearFromURL = regexp.MustCompile(`.*/(\d{4})/[^/]+$`)

func (p *processor) integrity(
	files []string,
	base string,
	mask whereType,
	lg func(string, ...interface{}),
) error {
	b, err := url.Parse(base)
	if err != nil {
		return err
	}
	client := p.httpClient()

	var data bytes.Buffer

	for _, f := range files {
		fp, err := url.Parse(f)
		if err != nil {
			lg("Bad URL %s: %v", f, err)
			continue
		}
		u := b.ResolveReference(fp).String()
		if p.markChecked(u, mask) {
			continue
		}
		p.checkTLS(u)
		res, err := client.Get(u)
		if err != nil {
			lg("Fetching %s failed: %v.", u, err)
			continue
		}
		if res.StatusCode != http.StatusOK {
			lg("Fetching %s failed: Status code %d (%s)",
				u, res.StatusCode, res.Status)
			continue
		}

		s256 := sha256.New()
		s512 := sha512.New()
		data.Reset()
		hasher := io.MultiWriter(s256, s512, &data)

		var doc interface{}

		if err := func() error {
			defer res.Body.Close()
			tee := io.TeeReader(res.Body, hasher)
			return json.NewDecoder(tee).Decode(&doc)
		}(); err != nil {
			lg("Reading %s failed: %v", u, err)
			continue
		}

		errors, err := csaf.ValidateCSAF(doc)
		if err != nil {
			lg("Failed to validate %s: %v", u, err)
			continue
		}
		if len(errors) > 0 {
			lg("CSAF file %s has %d validation errors.", u, len(errors))
		}

		// Check if file is in the right folder.
		use(&p.badFolders)

		if date, err := p.jsonPath(
			`$.document.tracking.initial_release_date`, doc); err != nil {
			p.badFolder(
				"Extracting 'initial_release_date' from %s failed: %v", u, err)
		} else if text, ok := date.(string); !ok {
			p.badFolder("'initial_release_date' is not a string in %s", u)
		} else if d, err := time.Parse(time.RFC3339, text); err != nil {
			p.badFolder(
				"Parsing 'initial_release_date' as RFC3339 failed in %s: %v", u, err)
		} else if m := yearFromURL.FindStringSubmatch(u); m == nil {
			p.badFolder("No year folder found in %s", u)
		} else if year, _ := strconv.Atoi(m[1]); d.UTC().Year() != year {
			p.badFolder("%s should be in folder %d", u, d.UTC().Year())
		}

		// Check hashes
		use(&p.badIntegrities)

		for _, x := range []struct {
			ext  string
			hash []byte
		}{
			{"sha256", s256.Sum(nil)},
			{"sha512", s512.Sum(nil)},
		} {
			hashFile := u + "." + x.ext
			p.checkTLS(hashFile)
			if res, err = client.Get(hashFile); err != nil {
				p.badIntegrity("Fetching %s failed: %v.", hashFile, err)
				continue
			}
			if res.StatusCode != http.StatusOK {
				p.badIntegrity("Fetching %s failed: Status code %d (%s)",
					hashFile, res.StatusCode, res.Status)
				continue
			}
			h, err := func() ([]byte, error) {
				defer res.Body.Close()
				return hashFromReader(res.Body)
			}()
			if err != nil {
				p.badIntegrity("Reading %s failed: %v.", hashFile, err)
				continue
			}
			if len(h) == 0 {
				p.badIntegrity("No hash found in %s.", hashFile)
				continue
			}
			if !bytes.Equal(h, x.hash) {
				p.badIntegrity("%s hash of %s does not match %s.",
					strings.ToUpper(x.ext), u, hashFile)
			}
		}

		// Check signature
		sigFile := u + ".asc"
		p.checkTLS(sigFile)

		use(&p.badSignatures)

		if res, err = client.Get(sigFile); err != nil {
			p.badSignature("Fetching %s failed: %v.", sigFile, err)
			continue
		}
		if res.StatusCode != http.StatusOK {
			p.badSignature("Fetching %s failed: status code %d (%s)",
				sigFile, res.StatusCode, res.Status)
			continue
		}

		sig, err := func() (*crypto.PGPSignature, error) {
			defer res.Body.Close()
			all, err := io.ReadAll(res.Body)
			if err != nil {
				return nil, err
			}
			return crypto.NewPGPSignatureFromArmored(string(all))
		}()
		if err != nil {
			p.badSignature("Loading signature from %s failed: %v.",
				sigFile, err)
			continue
		}

		if len(p.keys) > 0 {
			pm := crypto.NewPlainMessage(data.Bytes())
			t := crypto.GetUnixTime()
			var verified bool
			for _, key := range p.keys {
				if err := key.VerifyDetached(pm, sig, t); err == nil {
					verified = true
					break
				}
			}
			if !verified {
				p.badSignature("Signature of %s could not be verified.", u)
			}
		}
	}
	return nil
}

func (p *processor) processROLIEFeed(feed string) error {

	client := p.httpClient()
	res, err := client.Get(feed)
	if err != nil {
		p.badProviderMetadata("Cannot fetch feed %s: %v", feed, err)
		return errContinue
	}
	if res.StatusCode != http.StatusOK {
		p.badProviderMetadata("Fetching %s failed. Status code %d (%s)",
			feed, res.StatusCode, res.Status)
		return errContinue
	}
	rfeed, err := func() (*csaf.ROLIEFeed, error) {
		defer res.Body.Close()
		return csaf.LoadROLIEFeed(res.Body)
	}()
	if err != nil {
		p.badProviderMetadata("Loading ROLIE feed failed: %v.", err)
		return errContinue
	}
	base, err := basePath(feed)
	if err != nil {
		p.badProviderMetadata("Bad base path: %v", err)
		return errContinue
	}

	// Extract the CSAF files from feed.
	var files []string
	for _, f := range rfeed.Entry {
		for i := range f.Link {
			files = append(files, f.Link[i].HRef)
		}
	}

	if err := p.integrity(files, base, rolieMask, p.badProviderMetadata); err != nil &&
		err != errContinue {
		return err
	}

	if err := p.checkIndex(base, rolieIndexMask); err != nil && err != errContinue {
		return err
	}

	if err := p.checkChanges(base, rolieChangesMask); err != nil && err != errContinue {
		return err
	}

	return nil
}

func (p *processor) checkIndex(base string, mask whereType) error {
	client := p.httpClient()
	index := base + "/index.txt"
	p.checkTLS(index)

	use(&p.badIndices)

	res, err := client.Get(index)
	if err != nil {
		p.badIndex("Fetching %s failed: %v", index, err)
		return errContinue
	}
	if res.StatusCode != http.StatusOK {
		// It's optional
		if res.StatusCode != http.StatusNotFound {
			p.badIndex("Fetching %s failed. Status code %d (%s)",
				index, res.StatusCode, res.Status)
		}
		return errContinue
	}

	files, err := func() ([]string, error) {
		defer res.Body.Close()
		var files []string
		scanner := bufio.NewScanner(res.Body)
		for scanner.Scan() {
			files = append(files, scanner.Text())
		}
		return files, scanner.Err()
	}()
	if err != nil {
		p.badIndex("Reading %s failed: %v", index, err)
		return errContinue
	}

	return p.integrity(files, base, mask, p.badIndex)
}

func (p *processor) checkChanges(base string, mask whereType) error {
	client := p.httpClient()
	changes := base + "/changes.csv"
	p.checkTLS(changes)
	res, err := client.Get(changes)

	use(&p.badChanges)

	if err != nil {
		p.badChange("Fetching %s failed: %v", changes, err)
		return errContinue
	}
	if res.StatusCode != http.StatusOK {
		if res.StatusCode != http.StatusNotFound {
			// It's optional
			p.badChange("Fetching %s failed. Status code %d (%s)",
				changes, res.StatusCode, res.Status)
		}
		return errContinue
	}

	times, files, err := func() ([]time.Time, []string, error) {
		defer res.Body.Close()
		var times []time.Time
		var files []string
		c := csv.NewReader(res.Body)
		for {
			r, err := c.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, nil, err
			}
			if len(r) < 2 {
				return nil, nil, errors.New("not enough columns")
			}
			t, err := time.Parse(time.RFC3339, r[0])
			if err != nil {
				return nil, nil, err
			}
			times, files = append(times, t), append(files, r[1])
		}
		return times, files, nil
	}()
	if err != nil {
		p.badChange("Reading %s failed: %v", changes, err)
		return errContinue
	}

	if !sort.SliceIsSorted(times, func(i, j int) bool {
		return times[j].Before(times[i])
	}) {
		p.badChange("%s is not sorted in descending order", changes)
	}

	return p.integrity(files, base, mask, p.badChange)
}

func (p *processor) processROLIEFeeds(domain string, feeds [][]csaf.Feed) error {

	base, err := url.Parse(p.pmdURL)
	if err != nil {
		return err
	}
	for _, fs := range feeds {
		for i := range fs {
			feed := &fs[i]
			if feed.URL == nil {
				continue
			}
			up, err := url.Parse(string(*feed.URL))
			if err != nil {
				p.badProviderMetadata("Invalid URL %s in feed: %v.", *feed.URL, err)
				continue
			}
			feedURL := base.ResolveReference(up).String()
			p.checkTLS(feedURL)
			if err := p.processROLIEFeed(feedURL); err != nil && err != errContinue {
				return err
			}
		}
	}
	return nil
}

func (p *processor) checkCSAFs(domain string) error {
	// Check for ROLIE
	rolie, err := p.jsonPath("$.distributions[*].rolie.feeds", p.pmd)
	if err != nil {
		return err
	}

	fs, hasRolie := rolie.([]interface{})
	hasRolie = hasRolie && len(fs) > 0

	if hasRolie {
		var feeds [][]csaf.Feed
		if err := util.ReMarshalJSON(&feeds, rolie); err != nil {
			p.badProviderMetadata("ROLIE feeds are not compatible: %v.", err)
		} else if err := p.processROLIEFeeds(domain, feeds); err != nil {
			if err != errContinue {
				return err
			}
		}
	}

	// No rolie feeds
	base, err := basePath(p.pmdURL)
	if err != nil {
		return err
	}

	if err := p.checkIndex(base, indexMask); err != nil && err != errContinue {
		return err
	}

	if err := p.checkChanges(base, changesMask); err != nil && err != errContinue {
		return err
	}

	return nil
}

func (p *processor) checkMissing(string) error {
	var maxMask whereType

	for _, v := range p.alreadyChecked {
		maxMask |= v
	}

	var files []string

	for f, v := range p.alreadyChecked {
		if v != maxMask {
			files = append(files, f)
		}
	}
	sort.Strings(files)
	for _, f := range files {
		v := p.alreadyChecked[f]
		var where []string
		for mask := rolieMask; mask <= changesMask; mask <<= 1 {
			if maxMask&mask == mask {
				var in string
				if v&mask == mask {
					in = "in"
				} else {
					in = "not in"
				}
				where = append(where, in+" "+mask.String())
			}
		}
		p.badIntegrity("%s %s", f, strings.Join(where, ", "))
	}
	return nil
}

var providerMetadataLocations = [...]string{
	".well-known/csaf",
	"security/data/csaf",
	"advisories/csaf",
	"security/csaf",
}

// locateProviderMetadata searches for provider-metadata.json at various
// locations mentioned in "7.1.7 Requirement 7: provider-metadata.json".
func (p *processor) locateProviderMetadata(
	domain string,
	found func(string, io.Reader) error,
) error {

	client := p.httpClient()

	tryURL := func(url string) (bool, error) {
		res, err := client.Get(url)
		if err != nil || res.StatusCode != http.StatusOK ||
			res.Header.Get("Content-Type") != "application/json" {
			// ignore this as it is expected.
			return false, nil
		}

		if err := func() error {
			defer res.Body.Close()
			return found(url, res.Body)
		}(); err != nil {
			return false, err
		}
		return true, nil
	}

	for _, loc := range providerMetadataLocations {
		url := "https://" + domain + "/" + loc
		ok, err := tryURL(url)
		if err != nil {
			if err == errContinue {
				continue
			}
			return err
		}
		if ok {
			return nil
		}
	}

	// Read from security.txt

	path := "https://" + domain + "/.well-known/security.txt"
	res, err := client.Get(path)
	if err != nil {
		return err
	}

	if res.StatusCode != http.StatusOK {
		return err
	}

	loc, err := func() (string, error) {
		defer res.Body.Close()
		return extractProviderURL(res.Body)
	}()

	if err != nil {
		log.Printf("error: %v\n", err)
		return nil
	}

	if loc != "" {
		if _, err = tryURL(loc); err == errContinue {
			err = nil
		}
	}

	return err
}

func extractProviderURL(r io.Reader) (string, error) {
	sc := bufio.NewScanner(r)
	const csaf = "CSAF:"

	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, csaf) {
			line = strings.TrimSpace(line[len(csaf):])
			if !strings.HasPrefix(line, "https://") {
				return "", errors.New("CASF: found in security.txt, but does not start with https://")
			}
			return line, nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", nil
}

func (p *processor) checkProviderMetadata(domain string) error {

	use(&p.badProviderMetadatas)

	found := func(url string, content io.Reader) error {

		// Calculate checksum for later comparison.
		hash := sha256.New()

		tee := io.TeeReader(content, hash)
		if err := json.NewDecoder(tee).Decode(&p.pmd); err != nil {
			p.badProviderMetadata("%s: Decoding JSON failed: %v", url, err)
			return errContinue
		}

		p.pmd256 = hash.Sum(nil)

		errors, err := csaf.ValidateProviderMetadata(p.pmd)
		if err != nil {
			return err
		}
		if len(errors) > 0 {
			p.badProviderMetadata("%s: Validating against JSON schema failed:", url)
			for _, msg := range errors {
				p.badProviderMetadata(strings.ReplaceAll(msg, `%`, `%%`))
			}
			return errStop
		}
		p.pmdURL = url
		return nil
	}

	if err := p.locateProviderMetadata(domain, found); err != nil {
		return err
	}

	if p.pmdURL == "" {
		p.badProviderMetadata("No provider-metadata.json found.")
		return errStop
	}
	return nil
}

func (p *processor) checkSecurity(domain string) error {

	client := p.httpClient()

	use(&p.badSecurities)

	path := "https://" + domain + "/.well-known/security.txt"
	res, err := client.Get(path)
	if err != nil {
		p.badSecurity("Fetching %s failed: %v", path, err)
		return errContinue
	}

	if res.StatusCode != http.StatusOK {
		p.badSecurity("Fetching %s failed. Status code %d (%s)",
			path, res.StatusCode, res.Status)
		return errContinue
	}

	u, err := func() (string, error) {
		defer res.Body.Close()
		lines := bufio.NewScanner(res.Body)
		for lines.Scan() {
			line := lines.Text()
			if strings.HasPrefix(line, "CSAF:") {
				return strings.TrimSpace(line[6:]), nil
			}
		}
		return "", lines.Err()
	}()
	if err != nil {
		p.badSecurity("Error while reading security.txt: %v", err)
		return errContinue
	}
	if u == "" {
		p.badSecurity("No CSAF line found in security.txt.")
		return errContinue
	}

	// Try to load
	up, err := url.Parse(u)
	if err != nil {
		p.badSecurity("CSAF URL '%s' invalid: %v", u, err)
		return errContinue
	}

	base, err := url.Parse("https://" + domain + "/.well-known/")
	if err != nil {
		return err
	}

	u = base.ResolveReference(up).String()
	p.checkTLS(u)
	if res, err = client.Get(u); err != nil {
		p.badSecurity("Cannot fetch %s from security.txt: %v", u, err)
		return errContinue
	}
	if res.StatusCode != http.StatusOK {
		p.badSecurity("Fetching %s failed. Status code %d (%s)",
			u, res.StatusCode, res.Status)
		return errContinue
	}
	defer res.Body.Close()
	// Compare checksums to already read provider-metadata.json.
	h := sha256.New()
	if _, err := io.Copy(h, res.Body); err != nil {
		p.badSecurity("Reading %s failed: %v", u, err)
		return errContinue
	}

	if !bytes.Equal(h.Sum(nil), p.pmd256) {
		p.badSecurity("Content of %s from security.txt is not "+
			"identical to .well-known/csaf/provider-metadata.json", u)
	}

	return nil
}

func (p *processor) checkPGPKeys(domain string) error {

	use(&p.badPGPs)

	src, err := p.jsonPath("$.pgp_keys", p.pmd)
	if err != nil {
		p.badPGP("No PGP keys found: %v.", err)
		return errContinue
	}

	var keys []csaf.PGPKey
	if err := util.ReMarshalJSON(&keys, src); err != nil {
		p.badPGP("PGP keys invalid: %v.", err)
		return errContinue
	}

	if len(keys) == 0 {
		p.badPGP("No PGP keys found.")
		return errContinue
	}

	// Try to load

	client := p.httpClient()

	base, err := url.Parse(p.pmdURL)
	if err != nil {
		return err
	}

	for i := range keys {
		key := &keys[i]
		if key.URL == nil {
			p.badPGP("Missing URL for fingerprint %x.", key.Fingerprint)
			continue
		}
		up, err := url.Parse(*key.URL)
		if err != nil {
			p.badPGP("Invalid URL '%s': %v", *key.URL, err)
			continue
		}

		u := base.ResolveReference(up).String()
		p.checkTLS(u)

		res, err := client.Get(u)
		if err != nil {
			p.badPGP("Fetching PGP key %s failed: %v.", u, err)
			continue
		}
		if res.StatusCode != http.StatusOK {
			p.badPGP("Fetching PGP key %s status code: %d (%s)",
				u, res.StatusCode, res.Status)
			continue
		}

		ckey, err := func() (*crypto.Key, error) {
			defer res.Body.Close()
			return crypto.NewKeyFromArmoredReader(res.Body)
		}()

		if err != nil {
			p.badPGP("Reading PGP key %s failed: %v", u, err)
			continue
		}

		if ckey.GetFingerprint() != string(key.Fingerprint) {
			p.badPGP("Fingerprint of PGP key %s do not match remotely loaded.", u)
			continue
		}
		keyring, err := crypto.NewKeyRing(ckey)
		if err != nil {
			p.badPGP("Creating key ring for %s failed: %v.", u, err)
			continue
		}
		p.keys = append(p.keys, keyring)
	}

	if len(p.keys) == 0 {
		p.badPGP("No PGP keys loaded.")
	}
	return nil
}
