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
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/csaf-poc/csaf_distribution/csaf"
)

type pmdResult struct {
	url      string
	pmd      interface{}
	hash     []byte
	messages []string
}

func (p *processor) loadProviderMetadata(url string) *pmdResult {
	client := p.httpClient()

	res, err := client.Get(url)

	if err != nil || res.StatusCode != http.StatusOK {
		// Treat as not found.
		return nil
	}

	// TODO: Check for application/json and log it.

	defer res.Body.Close()

	// Calculate checksum for later comparison.
	hash := sha256.New()

	result := pmdResult{url: url}

	tee := io.TeeReader(res.Body, hash)

	if err := json.NewDecoder(tee).Decode(&result.pmd); err != nil {
		result.messages = []string{fmt.Sprintf("%s: Decoding JSON failed: %v", url, err)}
		return &result
	}

	result.hash = hash.Sum(nil)

	errors, err := csaf.ValidateProviderMetadata(result.pmd)
	if err != nil {
		result.messages = []string{
			fmt.Sprintf("%s: Validating against JSON schema failed: %v", url, err)}
		return &result
	}

	if len(errors) > 0 {
		result.messages = []string{
			fmt.Sprintf("%s: Validating against JSON schema failed: %v", url, err)}
		for _, msg := range errors {
			result.messages = append(result.messages, strings.ReplaceAll(msg, `%`, `%%`))
		}
	}

	return &result
}

func (p *processor) loadProviderMetadatasFromSecurity(path string) ([]*pmdResult, error) {

	client := p.httpClient()

	res, err := client.Get(path)

	if err != nil || res.StatusCode != http.StatusOK {
		// Treat as not found.
		return nil, nil
	}

	// Extract all potential URLs from CSAF.
	urls, err := func() ([]string, error) {
		defer res.Body.Close()
		return csaf.ExtractProviderURL(res.Body, true)
	}()

	if err != nil {
		return nil, err
	}

	var results []*pmdResult

	// Load the URLs
	for _, url := range urls {
		if result := p.loadProviderMetadata(url); result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}

func (p *processor) findProviderMetadata(domain string) *pmdResult {

	p.badProviderMetadata.use()

	// Valid provider metadata under well-known.
	var wellknownGood *pmdResult

	// First try well-know path
	wellknownURL := "https://" + domain + "/.well-known/csaf/provider-metadata.json"
	log.Printf("Trying: %s\n", wellknownURL)
	wellknownResult := p.loadProviderMetadata(wellknownURL)

	if wellknownResult == nil {
		p.badProviderMetadata.add("%s not found.", wellknownURL)
	} else if len(wellknownResult.messages) > 0 {
		// There are issues
		for _, msg := range wellknownResult.messages {
			p.badProviderMetadata.add(msg)
		}
	} else {
		// We have a candidate.
		wellknownGood = wellknownResult
	}

	// Next load the PMDs from security.txt
	secURL := "https://" + domain + "/.well-known/security.txt"
	log.Printf("Trying: %s\n", secURL)
	secResults, err := p.loadProviderMetadatasFromSecurity(secURL)

	if err != nil {
		p.badProviderMetadata.add("%s failed: %v.", secURL, err)
	} else {
		// Filter out the results which are valid.
		var secGoods []*pmdResult

		for _, result := range secResults {
			if len(result.messages) > 0 {
				for _, msg := range result.messages {
					p.badProviderMetadata.add(msg)
				}
			} else {
				secGoods = append(secGoods, result)
			}
		}

		// security.txt contains good entries.
		if len(secGoods) > 0 {
			// we have a wellknown good take it.
			if wellknownGood != nil {
				// check if first of security urls is identical to wellknown.
				if bytes.Equal(wellknownGood.hash, secGoods[0].hash) {
					// Mention extra CSAF entries
					for _, extra := range secGoods[1:] {
						p.badProviderMetadata.add("Ignoring extra CSAF entry in security.txt: %s", extra.url)
					}
				} else {
					// Complaint about not matching.
					p.badProviderMetadata.add("First entry of security.txt and well-known don't match.")
					// List all the security urls.
					for _, sec := range secGoods {
						p.badProviderMetadata.add("Ignoring CSAF entry in security.txt: %s", sec.url)
					}
				}
				// Take the good well-known.
				return wellknownGood
			}

			// Don't have well-known. Take first good from security.txt.
			// Mention extra CSAF entries
			for _, extra := range secGoods[1:] {
				p.badProviderMetadata.add("Ignoring extra CSAF entry in security.txt: %s", extra.url)
			}

			return secGoods[0]
		}
	}

	// If we have a good well-known take it.
	if wellknownGood != nil {
		return wellknownGood
	}

	// Last resort fall back to DNS.

	dnsURL := "https://csaf.data.security." + domain
	log.Printf("Trying: %s\n", dnsURL)
	dnsResult := p.loadProviderMetadata(dnsURL)

	if dnsResult == nil {
		p.badProviderMetadata.add("%s not found.", dnsURL)
	} else if len(dnsResult.messages) > 0 {
		for _, msg := range dnsResult.messages {
			p.badProviderMetadata.add(msg)
		}
	} else {
		// DNS seems to be okay.
		return dnsResult
	}

	// We failed all.
	return nil
}
