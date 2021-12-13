// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/csaf-poc/csaf_distribution/csaf"
)

type processor struct {
	opts      *options
	redirects map[string]string
}

type check interface {
	executeOrder() int
	run(*processor, string) error
	report(*processor, *Domain)
}

func newProcessor(opts *options) *processor {
	return &processor{
		opts:      opts,
		redirects: map[string]string{},
	}
}

func (p *processor) clean() {
	for k := range p.redirects {
		delete(p.redirects, k)
	}
}

func (p *processor) run(checks []check, domains []string) (*Report, error) {

	var report Report

	execs := make([]check, len(checks))
	copy(execs, checks)
	sort.SliceStable(execs, func(i, j int) bool {
		return execs[i].executeOrder() < execs[j].executeOrder()
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

func (p *processor) checkRedirect(r *http.Request, via []*http.Request) error {

	var path strings.Builder
	for i, v := range via {
		if i > 0 {
			path.WriteString(", ")
		}
		path.WriteString(v.URL.String())
	}
	p.redirects[r.URL.String()] = path.String()

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

func (bc *baseCheck) executeOrder() int {
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

func (bc *baseCheck) ok(message string) bool {
	k := len(bc.messages) == 0
	if k {
		bc.messages = []string{message}
	}
	return k
}

func (tc *tlsCheck) run(p *processor, domain string) error {
	url := "https://" + domain + "/.well-known/csaf/provider-metadata.json"
	client := p.httpClient()
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return err
	}
	res, err := client.Do(req)
	if err != nil {
		msg := fmt.Sprintf("Fetching provider metadata failed: %s.", err.Error())
		tc.add(msg)
	}
	if res != nil && res.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("Status: %d (%s).", res.StatusCode, res.Status)
		tc.add(msg)
	}
	tc.ok("TLS check worked.")
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
		msg := fmt.Sprintf("Fetching provider metadata failed: %s.", err.Error())
		pmdc.add(msg)
		return nil
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("Status: %d (%s).", res.StatusCode, res.Status)
		pmdc.add(msg)
	}
	var doc interface{}
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		msg := fmt.Sprintf("Decoding JSON failed: %s.", err.Error())
		pmdc.add(msg)
	}
	errors, err := csaf.ValidateProviderMetadata(doc)
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

func (sc *securityCheck) run(*processor, string) error {
	// TODO: Implement me!
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

func (ppkc *publicPGPKeyCheck) run(*processor, string) error {
	// TODO: Implement me!
	return nil
}
