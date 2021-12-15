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
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/csaf-poc/csaf_distribution/csaf"
	"github.com/csaf-poc/csaf_distribution/util"
)

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

	if err := p.checkProviderMetadata(domain, pmdc.sprintf); err != nil {
		return err
	}

	pmdc.ok("No problems with provider metadata.")
	return nil
}

func (sc *securityCheck) run(p *processor, domain string) error {
	path := "https://" + domain + "/.well-known/security.txt"
	client := p.httpClient()
	res, err := client.Get(path)
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
	if res, err = client.Get(u); err != nil {
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

func (ofpyc *oneFolderPerYearCheck) run(p *processor, domain string) error {

	// TODO: This does not belong here!
	return p.checkCSAFs(domain, ofpyc.sprintf)
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

		res, err := client.Get(u)
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
