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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	keys           []*crypto.KeyRing

	badHashes            []string
	badPGPs              []string
	badSignatures        []string
	badProviderMetadatas []string
	badSecurity          []string
	badIntegrity         []string

	builder gval.Language
	exprs   map[string]gval.Evaluable
}

type Reporter interface {
	report(*processor, *Domain)
}

var errContinue = errors.New("continue")

func newProcessor(opts *options) *processor {
	return &processor{
		opts:           opts,
		redirects:      map[string]string{},
		noneTLS:        map[string]struct{}{},
		alreadyChecked: map[string]struct{}{},
		builder:        gval.Full(jsonpath.Language()),
		exprs:          map[string]gval.Evaluable{},
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

	p.badHashes = nil
	p.badPGPs = nil
	p.badSignatures = nil
	p.badProviderMetadatas = nil
	p.badSecurity = nil
	p.badIntegrity = nil
}

func (p *processor) run(reporter []Reporter, domains []string) (*Report, error) {

	var report Report

domainsLoop:
	for _, d := range domains {
		if err := p.checkDomain(d); err != nil {
			if err == errContinue {
				continue domainsLoop
			}
			return nil, err
		}
		domain := &Domain{Name: d}
		for _, ch := range reporter {
			ch.report(p, domain)
		}
		report.Domains = append(report.Domains, domain)
		p.clean()
	}

	return &report, nil
}

func (p *processor) checkDomain(domain string) error {

	// TODO: Implement me!
	if err := p.checkProviderMetadata(domain); err != nil && err != errContinue {
		return err
	}
	return nil
}

func (p *processor) jsonPath(expr string) (interface{}, error) {
	if p.pmd == nil {
		return nil, errors.New("no provider metadata loaded")
	}
	eval := p.exprs[expr]
	if eval == nil {
		var err error
		if eval, err = p.builder.NewEvaluable(expr); err != nil {
			return nil, err
		}
		p.exprs[expr] = eval
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

func (p *processor) badHash(format string, args ...interface{}) {
	p.badHashes = append(p.badHashes, fmt.Sprintf(format, args...))
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

	var data bytes.Buffer

	for _, f := range files {
		fp, err := url.Parse(f)
		if err != nil {
			lg("Bad URL %s: %v", f, err)
			continue
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

		// Check hashes
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
				p.badHash("Fetching %s failed: %v.", hashFile, err)
				continue
			}
			if res.StatusCode != http.StatusOK {
				p.badHash("Fetching %s failed: Status code %d (%s)",
					hashFile, res.StatusCode, res.Status)
				continue
			}
			h, err := func() ([]byte, error) {
				defer res.Body.Close()
				return hashFromReader(res.Body)
			}()
			if err != nil {
				p.badHash("Reading %s failed: %v.", hashFile, err)
				continue
			}
			if len(h) == 0 {
				p.badHash("No hash found in %s.", hashFile)
				continue
			}
			if !bytes.Equal(h, x.hash) {
				p.badHash("%s hash of %s does not match %s.",
					strings.ToUpper(x.ext), u, hashFile)
			}
		}

		// Check signature
		sigFile := u + ".asc"
		p.checkTLS(sigFile)

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

func (p *processor) processFeed(feed string, lg func(string, ...interface{})) error {

	client := p.httpClient()
	res, err := client.Get(feed)
	if err != nil {
		lg("Cannot fetch feed %s: %v", feed, err)
		return errContinue
	}
	if res.StatusCode != http.StatusOK {
		lg("Fetching %s failed. Status code %d (%s)",
			feed, res.StatusCode, res.Status)
		return errContinue
	}
	rfeed, err := func() (*csaf.ROLIEFeed, error) {
		defer res.Body.Close()
		return csaf.LoadROLIEFeed(res.Body)
	}()
	if err != nil {
		lg("Loading ROLIE feed failed: %v.", err)
		return errContinue
	}
	base, err := basePath(feed)
	if err != nil {
		lg("Bad base path: %v", err)
		return errContinue
	}

	// Extract the CSAF files from feed.
	var files []string
	for _, f := range rfeed.Entry {
		for i := range f.Link {
			files = append(files, f.Link[i].HRef)
		}
	}
	return p.integrity(files, base, lg)
}

func (p *processor) processFeeds(
	domain string,
	feeds [][]csaf.Feed,
	lg func(string, ...interface{}),
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
				lg("Invalid URL %s in feed: %v.", *feed.URL, err)
				continue
			}
			feedURL := base.ResolveReference(up).String()
			p.checkTLS(feedURL)
			if err := p.processFeed(feedURL, lg); err != nil && err != errContinue {
				return err
			}
		}
	}
	return nil
}

func (p *processor) checkCSAFs(domain string, lg func(string, ...interface{})) error {
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
			lg("ROLIE feeds are not compatible: %v.", err)
			goto noRolie
		}
		if err := p.processFeeds(domain, feeds, lg); err != nil {
			if err == errContinue {
				goto noRolie
			}
			return err
		}
	}

noRolie:

	// No rolie feeds
	// TODO: Implement me!

	return nil
}

func (p *processor) checkProviderMetadata(domain string) error {

	client := p.httpClient()

	url := "https://" + domain + "/.well-known/csaf/provider-metadata.json"

	res, err := client.Get(url)
	if err != nil {
		p.badProviderMetadata("Fetching %s: %v.", url, err)
		return errContinue
	}

	if res.StatusCode != http.StatusOK {
		p.badProviderMetadata("Fetching %s failed. Status code: %d (%s)",
			url, res.StatusCode, res.Status)
		return errContinue
	}

	// Calculate checksum for later comparison.
	hash := sha256.New()

	if err := func() error {
		defer res.Body.Close()
		tee := io.TeeReader(res.Body, hash)
		return json.NewDecoder(tee).Decode(&p.pmd)
	}(); err != nil {
		p.badProviderMetadata("Decoding JSON failed: %v", err)
		return errContinue
	}

	p.pmd256 = hash.Sum(nil)

	errors, err := csaf.ValidateProviderMetadata(p.pmd)
	if err != nil {
		return err
	}
	if len(errors) > 0 {
		p.badProviderMetadata("Validating against JSON schema failed:")
		for _, msg := range errors {
			p.badProviderMetadata(strings.ReplaceAll(msg, `%`, `%%`))
		}
	}
	return nil
}

func (p *processor) checkSecurity(domain string, lg func(string, ...interface{})) error {

	client := p.httpClient()

	path := "https://" + domain + "/.well-known/security.txt"
	res, err := client.Get(path)
	if err != nil {
		lg("Fetchinig %s failed: %v", err)
		return errContinue
	}

	if res.StatusCode != http.StatusOK {
		lg("Fetching %s failed. Status code %d (%s)",
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
		lg("Error while reading security.txt: %v", err)
		return errContinue
	}
	if u == "" {
		lg("No CSAF line found in security.txt.")
		return errContinue
	}

	// Try to load
	up, err := url.Parse(u)
	if err != nil {
		lg("CSAF URL '%s' invalid: %v", u, err)
		return errContinue
	}

	base, err := url.Parse("https://" + domain + "/.well-known/")
	if err != nil {
		return err
	}

	u = base.ResolveReference(up).String()
	p.checkTLS(u)
	if res, err = client.Get(u); err != nil {
		lg("Cannot fetch %s from security.txt: %v", u, err)
		return errContinue
	}
	if res.StatusCode != http.StatusOK {
		lg("Fetching %s failed. Status code %d (%s)",
			u, res.StatusCode, res.Status)
		return errContinue
	}
	defer res.Body.Close()
	// Compare checksums to already read provider-metadata.json.
	h := sha256.New()
	if _, err := io.Copy(h, res.Body); err != nil {
		lg("Reading %s failed: %v", u, err)
		return errContinue
	}

	if !bytes.Equal(h.Sum(nil), p.pmd256) {
		lg("Content of %s from security.txt is not identical to .well-known/csaf/provider-metadata.json", u)
	}

	return nil
}

func (p *processor) checkPGPKeys(domain string, lg func(string, ...interface{})) error {

	src, err := p.jsonPath("$.pgp_keys")
	if err != nil {
		lg("No PGP keys found: %v.", err)
		return errContinue
	}

	var keys []csaf.PGPKey
	if err := util.ReMarshalJSON(&keys, src); err != nil {
		lg("PGP keys invalid: %v.", err)
		return errContinue
	}

	if len(keys) == 0 {
		lg("No PGP keys found.")
		return errContinue
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
			lg("Missing URL for fingerprint %x.", key.Fingerprint)
			continue
		}
		up, err := url.Parse(*key.URL)
		if err != nil {
			lg("Invalid URL '%s': %v", *key.URL, err)
			continue
		}

		u := base.ResolveReference(up).String()
		p.checkTLS(u)

		res, err := client.Get(u)
		if err != nil {
			lg("Fetching PGP key %s failed: %v.", u, err)
			continue
		}
		if res.StatusCode != http.StatusOK {
			lg("Fetching PGP key %s status code: %d (%s)", u, res.StatusCode, res.Status)
			continue
		}

		ckey, err := func() (*crypto.Key, error) {
			defer res.Body.Close()
			return crypto.NewKeyFromArmoredReader(res.Body)
		}()

		if err != nil {
			lg("Reading PGP key %s failed: %v", u, err)
			continue
		}

		if ckey.GetFingerprint() != string(key.Fingerprint) {
			lg("Fingerprint of PGP key %s do not match remotely loaded.", u)
			continue
		}
		keyring, err := crypto.NewKeyRing(ckey)
		if err != nil {
			lg("Creating key ring for %s failed: %v.", u, err)
			continue
		}
		p.keys = append(p.keys, keyring)
	}

	if len(p.keys) == 0 {
		lg("No PGP keys loaded.")
	}
	return nil
}