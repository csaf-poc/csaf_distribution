// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package main

import (
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
			if !bytes.Equal(h, x.hash) {
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
				p.addBadSignature("Signature of %s could not be verified.", u)
			}
		}
	}
	return nil
}

func (p *processor) processFeed(feed string, lg func(string, ...interface{})) error {

	client := p.httpClient()
	res, err := client.Get(feed)
	if err != nil {
		lg("Cannot fetch feed %s: %v.", feed, err)
		return nil
	}
	if res.StatusCode != http.StatusOK {
		lg("Fetching %s failed. Status code %d (%s)",
			feed, res.StatusCode, res.Status)
		return nil
	}
	rfeed, err := func() (*csaf.ROLIEFeed, error) {
		defer res.Body.Close()
		return csaf.LoadROLIEFeed(res.Body)
	}()
	if err != nil {
		lg("Loading ROLIE feed failed: %v.", err)
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
			if err := p.processFeed(feedURL, lg); err != nil {
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
			return nil
		}
		if err := p.processFeeds(domain, feeds, lg); err != nil {
			return err
		}
	} else {
		// No rolie feeds
		// TODO: Implement me!
	}

	return nil
}
