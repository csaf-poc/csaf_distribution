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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/PaesslerAG/gval"
	"github.com/PaesslerAG/jsonpath"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/csaf-poc/csaf_distribution/csaf"
	"github.com/csaf-poc/csaf_distribution/util"
)

type processor struct {
	opts           *options
	redirects      map[string]string
	noneTLS        map[string]struct{}
	alreadyChecked map[string]struct{}
	pmd256         []byte
	pmd            interface{}
	builder        gval.Language
	keys           []*crypto.KeyRing
	badHashes      []string
	badSignatures  []string
}

type check interface {
	executionOrder() int
	run(*processor, string) error
	report(*processor, *Domain)
}

func newProcessor(opts *options) *processor {
	return &processor{
		opts:           opts,
		redirects:      map[string]string{},
		noneTLS:        map[string]struct{}{},
		alreadyChecked: map[string]struct{}{},
		builder:        gval.Full(jsonpath.Language()),
	}
}

func (p *processor) clean() {
	for k := range p.redirects {
		delete(p.redirects, k)
	}
	for k := range p.noneTLS {
		delete(p.noneTLS, k)
	}
	for k := range p.alreadyChecked {
		delete(p.alreadyChecked, k)
	}
	p.pmd256 = nil
	p.pmd = nil
	p.keys = nil
	p.badSignatures = nil
	p.badHashes = nil
}

func (p *processor) run(checks []check, domains []string) (*Report, error) {

	var report Report

	execs := make([]check, len(checks))
	copy(execs, checks)
	sort.SliceStable(execs, func(i, j int) bool {
		return execs[i].executionOrder() < execs[j].executionOrder()
	})

	for _, d := range domains {
		for _, ch := range execs {
			if err := ch.run(p, d); err != nil {
				return nil, err
			}
		}
		domain := &Domain{Name: d}
		for _, ch := range checks {
			ch.report(p, domain)
		}
		report.Domains = append(report.Domains, domain)
		p.clean()
	}

	return &report, nil
}

func (p *processor) jsonPath(expr string) (interface{}, error) {
	if p.pmd == nil {
		return nil, errors.New("no provider metadata loaded")
	}
	eval, err := p.builder.NewEvaluable(expr)
	if err != nil {
		return nil, err
	}
	return eval(context.Background(), p.pmd)
}

func (p *processor) checkTLS(u string) {
	if x, err := url.Parse(u); err == nil && x.Scheme != "https" {
		p.noneTLS[u] = struct{}{}
	}
}

func (p *processor) markChecked(s string) bool {
	if _, ok := p.alreadyChecked[s]; ok {
		return true
	}
	p.alreadyChecked[s] = struct{}{}
	return false
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
	p.redirects[url] = path.String()

	if len(via) > 10 {
		return errors.New("Too many redirections")
	}
	return nil
}

func (p *processor) httpClient() *http.Client {
	client := http.Client{
		CheckRedirect: p.checkRedirect,
	}

	if p.opts.Insecure {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	}

	return &client
}

func (p *processor) addBadHash(format string, args ...interface{}) {
	p.badHashes = append(p.badHashes, fmt.Sprintf(format, args...))
}

func (p *processor) addBadSignature(format string, args ...interface{}) {
	p.badSignatures = append(p.badSignatures, fmt.Sprintf(format, args...))
}

func (p *processor) integrity(
	files []string,
	base string,
	lg func(string, ...interface{}),
) error {
	b, err := url.Parse(base)
	if err != nil {
		return err
	}
	client := p.httpClient()
	for _, f := range files {
		fp, err := url.Parse(f)
		if err != nil {
			return err
		}
		u := b.ResolveReference(fp).String()
		if p.markChecked(u) {
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
		data, err := func() ([]byte, error) {
			defer res.Body.Close()
			return io.ReadAll(res.Body)
		}()
		if err != nil {
			lg("Reading %s failed: %v", u, err)
			continue
		}
		var doc interface{}
		if err := json.Unmarshal(data, &doc); err != nil {
			lg("Failed to unmarshal %s: %v", u, err)
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

		// Check hashes
		for _, x := range []struct {
			ext  string
			hash func() hash.Hash
		}{
			{"sha256", sha256.New},
			{"sha512", sha512.New},
		} {
			hashFile := u + "." + x.ext
			p.checkTLS(hashFile)
			if res, err = client.Get(hashFile); err != nil {
				p.addBadHash("Fetching %s failed: %v.", hashFile, err)
				continue
			}
			if res.StatusCode != http.StatusOK {
				p.addBadHash("Fetching %s failed: Status code %d (%s)",
					hashFile, res.StatusCode, res.Status)
				continue
			}
			h, err := func() ([]byte, error) {
				defer res.Body.Close()
				return hashFromReader(res.Body)
			}()
			if err != nil {
				p.addBadHash("Reading %s failed: %v.", hashFile, err)
				continue
			}
			if len(h) == 0 {
				p.addBadHash("No hash found in %s.", hashFile)
				continue
			}
			orig := x.hash()
			if _, err := orig.Write(data); err != nil {
				p.addBadHash("%s hashing of %s failed: %v.",
					strings.ToUpper(x.ext), u, err)
				continue
			}
			if !bytes.Equal(h, orig.Sum(nil)) {
				p.addBadHash("%s hash of %s does not match %s.",
					strings.ToUpper(x.ext), u, hashFile)
			}
		}

		// Check signature
		sigFile := u + ".asc"
		p.checkTLS(sigFile)

		if res, err = client.Get(sigFile); err != nil {
			p.addBadSignature("Fetching %s failed: %v.", sigFile, err)
			continue
		}
		if res.StatusCode != http.StatusOK {
			p.addBadSignature("Fetching %s failed: status code %d (%s)",
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
			p.addBadSignature("Loading signature from %s failed: %v.",
				sigFile, err)
			continue
		}

		if len(p.keys) > 0 {
			pm := crypto.NewPlainMessage(data)
			t := crypto.GetUnixTime()
			var verified bool
			for _, key := range p.keys {
				if err := key.VerifyDetached(pm, sig, t); err == nil {
					verified = true
					break
				}
			}
			if !verified {
				p.addBadSignature("Signature of %s could not be verified.", u)
			}
		}

	}
	return nil
}

var hexRe = regexp.MustCompile(`^([[:xdigit:]]+)`)

func hashFromReader(r io.Reader) ([]byte, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if m := hexRe.FindStringSubmatch(scanner.Text()); m != nil {
			return hex.DecodeString(m[1])
		}
	}
	return nil, scanner.Err()
}

type baseCheck struct {
	exec        int
	num         int
	description string
	messages    []string
}

type tlsCheck struct {
	baseCheck
}

type redirectsCheck struct {
	baseCheck
}

type providerMetadataCheck struct {
	baseCheck
}

type securityCheck struct {
	baseCheck
}

type wellknownMetadataCheck struct {
	baseCheck
}

type dnsPathCheck struct {
	baseCheck
}

type oneFolderPerYearCheck struct {
	baseCheck
}

type indexCheck struct {
	baseCheck
}

type changesCheck struct {
	baseCheck
}

type directoryListingsCheck struct {
	baseCheck
}

type integrityCheck struct {
	baseCheck
}

type signaturesCheck struct {
	baseCheck
}

type publicPGPKeyCheck struct {
	baseCheck
}

func (bc *baseCheck) executionOrder() int {
	return bc.exec
}

func (bc *baseCheck) run(*processor, string) error {
	return nil
}

func (bc *baseCheck) report(_ *processor, domain *Domain) {
	req := &Requirement{
		Num:         bc.num,
		Description: bc.description,
		Messages:    bc.messages,
	}
	domain.Requirements = append(domain.Requirements, req)
}

func (bc *baseCheck) add(messages ...string) {
	bc.messages = append(bc.messages, messages...)
}

func (bc *baseCheck) sprintf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	bc.messages = append(bc.messages, msg)
}

func (bc *baseCheck) ok(message string) bool {
	k := len(bc.messages) == 0
	if k {
		bc.messages = []string{message}
	}
	return k
}

func (tc *tlsCheck) run(p *processor, domain string) error {
	if len(p.noneTLS) == 0 {
		tc.add("All tested URLs were https.")
	} else {
		urls := make([]string, len(p.noneTLS))
		var i int
		for k := range p.noneTLS {
			urls[i] = k
			i++
		}
		sort.Strings(urls)
		tc.add("Following none https URLs were used:")
		tc.add(urls...)
	}
	return nil
}

func (rc *redirectsCheck) run(p *processor, domain string) error {
	if len(p.redirects) == 0 {
		rc.add("No redirections found.")
	} else {
		keys := make([]string, len(p.redirects))
		var i int
		for k := range p.redirects {
			keys[i] = k
			i++
		}
		sort.Strings(keys)
		for i, k := range keys {
			keys[i] = fmt.Sprintf("Redirect %s: %s", k, p.redirects[k])
		}
		rc.baseCheck.messages = keys
	}
	return nil
}

func (pmdc *providerMetadataCheck) run(p *processor, domain string) error {
	url := "https://" + domain + "/.well-known/csaf/provider-metadata.json"
	client := p.httpClient()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	res, err := client.Do(req)
	if err != nil {
		pmdc.sprintf("Fetching provider metadata failed: %s.", err.Error())
		return nil
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		pmdc.sprintf("Status: %d (%s).", res.StatusCode, res.Status)
	}

	// Calculate checksum for later comparison.
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, res.Body); err != nil {
		return err
	}
	data := buf.Bytes()
	h := sha256.New()
	if _, err := h.Write(data); err != nil {
		return err
	}
	p.pmd256 = h.Sum(nil)

	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&p.pmd); err != nil {
		pmdc.sprintf("Decoding JSON failed: %s.", err.Error())
	}
	errors, err := csaf.ValidateProviderMetadata(p.pmd)
	if err != nil {
		return err
	}
	if len(errors) > 0 {
		pmdc.add("Validating against JSON schema failed:")
		pmdc.add(errors...)
	}

	pmdc.ok("No problems with provider metadata.")
	return nil
}

func (sc *securityCheck) run(p *processor, domain string) error {
	path := "https://" + domain + "/.well-known/security.txt"
	client := p.httpClient()
	req, err := http.NewRequest(http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		sc.sprintf("Fetching security failed. Status code %d (%s)", res.StatusCode, res.Status)
		return nil
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
		sc.sprintf("Error while reading security.txt: %s", err.Error())
	}
	if u == "" {
		sc.add("No CSAF line found in security.txt.")
		return nil
	}

	// Try to load
	up, err := url.Parse(u)
	if err != nil {
		sc.sprintf("CSAF URL '%s' invalid: %s.", u, err.Error())
		return nil
	}

	base, err := url.Parse("https://" + domain + "/.well-known/")
	if err != nil {
		return err
	}
	ur := base.ResolveReference(up)
	u = ur.String()
	p.checkTLS(u)
	if req, err = http.NewRequest(http.MethodGet, u, nil); err != nil {
		return err
	}
	if res, err = client.Do(req); err != nil {
		sc.sprintf("Cannot fetch %s from security.txt: %v", u, err)
		return nil
	}
	if res.StatusCode != http.StatusOK {
		sc.sprintf("Fetching %s failed. Status code %d (%s).",
			u, res.StatusCode, res.Status)
		return nil
	}
	defer res.Body.Close()
	// Compare checksums to already read provider-metadata.json.
	h := sha256.New()
	if _, err := io.Copy(h, res.Body); err != nil {
		sc.sprintf("Reading %s failed: %v.", u, err)
		return nil
	}

	if !bytes.Equal(h.Sum(nil), p.pmd256) {
		sc.sprintf(
			"Content of %s from security.txt is not identical to .well-known/csaf/provider-metadata.json", u)
	}

	sc.ok("Valid CSAF line in security.txt found.")

	return nil
}

func (wmdc *wellknownMetadataCheck) run(*processor, string) error {
	// TODO: Implement me!
	return nil
}

func (dpc *dnsPathCheck) run(*processor, string) error {
	// TODO: Implement me!
	return nil
}

func basePath(p string) (string, error) {
	u, err := url.Parse(p)
	if err != nil {
		return "", err
	}
	ep := u.EscapedPath()
	if idx := strings.LastIndexByte(ep, '/'); idx != -1 {
		ep = ep[:idx]
	}
	user := u.User.String()
	if user != "" {
		user += "@"
	}
	return u.Scheme + "://" + user + u.Host + "/" + ep, nil
}

func (ofpyc *oneFolderPerYearCheck) processFeed(
	p *processor,
	feed string,
) error {
	client := p.httpClient()
	res, err := client.Get(feed)
	if err != nil {
		ofpyc.sprintf("Cannot fetch feed %s: %v.", feed, err)
		return nil
	}
	if res.StatusCode != http.StatusOK {
		ofpyc.sprintf("Fetching %s failed. Status code %d (%s)",
			feed, res.StatusCode, res.Status)
		return nil
	}
	rfeed, err := func() (*csaf.ROLIEFeed, error) {
		defer res.Body.Close()
		return csaf.LoadROLIEFeed(res.Body)
	}()
	if err != nil {
		ofpyc.sprintf("Loading ROLIE feed failed: %v.", err)
		return nil
	}
	base, err := basePath(feed)
	if err != nil {
		return err
	}

	// Extract the CSAF files from feed.
	var files []string
	for _, f := range rfeed.Entry {
		for i := range f.Link {
			files = append(files, f.Link[i].HRef)
		}
	}
	return p.integrity(files, base, ofpyc.sprintf)
}

func (ofpyc *oneFolderPerYearCheck) processFeeds(
	p *processor,
	domain string,
	feeds [][]csaf.Feed,
) error {
	base, err := url.Parse("https://" + domain + "/.well-known/csaf/")
	if err != nil {
		return err
	}
	for i := range feeds {
		for j := range feeds[i] {
			feed := &feeds[i][j]
			if feed.URL == nil {
				continue
			}
			up, err := url.Parse(string(*feed.URL))
			if err != nil {
				ofpyc.sprintf("Invalid URL %s in feed: %v.", *feed.URL, err)
				continue
			}
			feedURL := base.ResolveReference(up).String()
			p.checkTLS(feedURL)
			if err := ofpyc.processFeed(p, feedURL); err != nil {
				return err
			}
		}
	}
	return nil
}

func (ofpyc *oneFolderPerYearCheck) run(p *processor, domain string) error {
	// Check for ROLIE
	rolie, err := p.jsonPath("$.distributions[*].rolie.feeds")
	if err != nil {
		return err
	}

	fs, hasRolie := rolie.([]interface{})
	hasRolie = hasRolie && len(fs) > 0

	if hasRolie {
		var feeds [][]csaf.Feed
		if err := util.ReMarshalJSON(&feeds, rolie); err != nil {
			ofpyc.sprintf("ROLIE feeds are not compatible: %v.", err)
			return nil
		}
		if err := ofpyc.processFeeds(p, domain, feeds); err != nil {
			return err
		}
	} else {
		// No rolie feeds
		// TODO: Implement me!
	}

	return nil
}

func (ic *indexCheck) run(*processor, string) error {
	// TODO: Implement me!
	return nil
}

func (cc *changesCheck) run(*processor, string) error {
	// TODO: Implement me!
	return nil
}

func (dlc *directoryListingsCheck) run(*processor, string) error {
	// TODO: Implement me!
	return nil
}

func (ic *integrityCheck) run(p *processor, _ string) error {
	if len(p.badHashes) > 0 {
		ic.baseCheck.messages = p.badHashes
	} else {
		ic.add("All checksums match.")
	}
	return nil
}

func (sc *signaturesCheck) run(p *processor, _ string) error {
	if len(p.badSignatures) > 0 {
		sc.baseCheck.messages = p.badSignatures
	} else {
		sc.add("All signatures verified.")
	}
	return nil
}

func reserialize(dst, src interface{}) error {
	s, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(s, dst)
}

func (ppkc *publicPGPKeyCheck) run(p *processor, domain string) error {

	src, err := p.jsonPath("$.pgp_keys")
	if err != nil {
		ppkc.sprintf("No PGP keys found: %v.", err)
		return nil
	}

	var keys []csaf.PGPKey
	if err := util.ReMarshalJSON(&keys, src); err != nil {
		ppkc.sprintf("PGP keys invalid: %v.", err)
		return nil
	}

	if len(keys) == 0 {
		ppkc.add("No PGP keys found.")
		return nil
	}

	// Try to load

	client := p.httpClient()

	base, err := url.Parse("https://" + domain + "/.well-known/csaf/provider-metadata.json")
	if err != nil {
		return err
	}

	for i := range keys {
		key := &keys[i]
		if key.URL == nil {
			ppkc.sprintf("Missing URL for fingerprint %x.", key.Fingerprint)
			continue
		}
		up, err := url.Parse(*key.URL)
		if err != nil {
			ppkc.sprintf("Invalid URL '%s': %v", *key.URL, err)
			continue
		}

		up = base.ResolveReference(up)
		u := up.String()
		p.checkTLS(u)

		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		res, err := client.Do(req)
		if err != nil {
			ppkc.sprintf("Fetching PGP key %s failed: %v.", u, err)
			continue
		}
		if res.StatusCode != http.StatusOK {
			ppkc.sprintf("Fetching PGP key %s status code: %d (%s)", u, res.StatusCode, res.Status)
			continue
		}

		ckey, err := func() (*crypto.Key, error) {
			defer res.Body.Close()
			return crypto.NewKeyFromArmoredReader(res.Body)
		}()

		if err != nil {
			ppkc.sprintf("Reading PGP key %s failed: %v", u, err)
			continue
		}

		if ckey.GetFingerprint() != string(key.Fingerprint) {
			ppkc.sprintf("Fingerprint of PGP key %s do not match remotely loaded.", u)
			continue
		}
		keyring, err := crypto.NewKeyRing(ckey)
		if err != nil {
			ppkc.sprintf("Creatin key ring for %s failed: %v.", u, err)
			continue
		}
		p.keys = append(p.keys, keyring)
	}

	if len(p.keys) == 0 {
		ppkc.add("No PGP keys loaded.")
		return nil
	}

	ppkc.ok(fmt.Sprintf("%d PGP key(s) loaded successfully.", len(p.keys)))

	return nil
}
