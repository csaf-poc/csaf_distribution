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
	opts      *options
	redirects map[string]string
	noneTLS   map[string]struct{}
	pmd256    []byte
	pmd       interface{}
	builder   gval.Language
	keys      []*crypto.Key
}

type check interface {
	executionOrder() int
	run(*processor, string) error
	report(*processor, *Domain)
}

func newProcessor(opts *options) *processor {
	return &processor{
		opts:      opts,
		redirects: map[string]string{},
		noneTLS:   map[string]struct{}{},
		builder:   gval.Full(jsonpath.Language()),
	}
}

func (p *processor) clean() {
	for k := range p.redirects {
		delete(p.redirects, k)
	}
	for k := range p.noneTLS {
		delete(p.noneTLS, k)
	}
	p.pmd256 = nil
	p.pmd = nil
	p.keys = nil
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

func (p *processor) checkTLS(url string) {
	if !strings.HasPrefix(strings.ToLower(url), "https://") {
		p.noneTLS[url] = struct{}{}
	}
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
		sc.sprintf("Cannot fetch %s from security.txt: %s", u, err.Error())
		return nil
	}
	if res.StatusCode != http.StatusOK {
		sc.sprintf("Fetching %s failed. Status code %d (%s).", u, res.StatusCode, res.Status)
		return nil
	}
	defer res.Body.Close()
	// Compare checksums to already read provider-metadata.json.
	h := sha256.New()
	if _, err := io.Copy(h, res.Body); err != nil {
		sc.sprintf("Reading %s failed: %s.", u, err.Error())
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

func (ofpyc *oneFolderPerYearCheck) report(p *processor, domain *Domain) {
	ofpyc.baseCheck.report(p, domain)
	// TODO: Implement me!
}

func (ofpyc *oneFolderPerYearCheck) run(*processor, string) error {
	// TODO: Implement me!
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

func (ic *integrityCheck) run(*processor, string) error {
	// TODO: Implement me!
	return nil
}

func (sc *signaturesCheck) run(*processor, string) error {
	// TODO: Implement me!
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
		p.keys = append(p.keys, ckey)
	}

	if len(p.keys) == 0 {
		ppkc.add("No PGP keys loaded.")
		return nil
	}

	ppkc.ok(fmt.Sprintf("%d PGP key(s) loaded successfully.", len(p.keys)))

	return nil
}
