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
	"github.com/csaf-poc/csaf_distribution/util"
)

type LoadedProviderMetadata struct {
	URL      string
	Document interface{}
	Hash     []byte
	Messages []string
}

func LoadProviderMetadata(client util.Client, url string) *LoadedProviderMetadata {

	res, err := client.Get(url)

	if err != nil || res.StatusCode != http.StatusOK {
		// Treat as not found.
		return nil
	}

	// TODO: Check for application/json and log it.

	defer res.Body.Close()

	// Calculate checksum for later comparison.
	hash := sha256.New()

	result := LoadedProviderMetadata{URL: url}

	tee := io.TeeReader(res.Body, hash)

	if err := json.NewDecoder(tee).Decode(&result.Document); err != nil {
		result.Messages = []string{fmt.Sprintf("%s: Decoding JSON failed: %v", url, err)}
		return &result
	}

	result.Hash = hash.Sum(nil)

	errors, err := csaf.ValidateProviderMetadata(result.Document)
	if err != nil {
		result.Messages = []string{
			fmt.Sprintf("%s: Validating against JSON schema failed: %v", url, err)}
		return &result
	}

	if len(errors) > 0 {
		result.Messages = []string{
			fmt.Sprintf("%s: Validating against JSON schema failed: %v", url, err)}
		for _, msg := range errors {
			result.Messages = append(result.Messages, strings.ReplaceAll(msg, `%`, `%%`))
		}
	}

	return &result
}

func LoadProviderMetadatasFromSecurity(client util.Client, path string) ([]*LoadedProviderMetadata, error) {

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

	var results []*LoadedProviderMetadata

	// Load the URLs
	for _, url := range urls {
		if result := LoadProviderMetadata(client, url); result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}

func (p *processor) LoadProviderMetadataForDomain(
	client util.Client,
	domain string,
	logging func(format string, args ...interface{}),
) *LoadedProviderMetadata {

	if logging == nil {
		logging = func(format string, args ...interface{}) {
			log.Printf("FindProviderMetadata: "+format+"\n", args...)
		}
	}

	// Valid provider metadata under well-known.
	var wellknownGood *LoadedProviderMetadata

	// First try well-know path
	wellknownURL := "https://" + domain + "/.well-known/csaf/provider-metadata.json"
	log.Printf("Trying: %s\n", wellknownURL)
	wellknownResult := LoadProviderMetadata(client, wellknownURL)

	if wellknownResult == nil {
		logging("%s not found.", wellknownURL)
	} else if len(wellknownResult.Messages) > 0 {
		// There are issues
		for _, msg := range wellknownResult.Messages {
			logging(msg)
		}
	} else {
		// We have a candidate.
		wellknownGood = wellknownResult
	}

	// Next load the PMDs from security.txt
	secURL := "https://" + domain + "/.well-known/security.txt"
	log.Printf("Trying: %s\n", secURL)
	secResults, err := LoadProviderMetadatasFromSecurity(client, secURL)

	if err != nil {
		logging("%s failed: %v.", secURL, err)
	} else {
		// Filter out the results which are valid.
		var secGoods []*LoadedProviderMetadata

		for _, result := range secResults {
			if len(result.Messages) > 0 {
				for _, msg := range result.Messages {
					logging(msg)
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
				if bytes.Equal(wellknownGood.Hash, secGoods[0].Hash) {
					// Mention extra CSAF entries
					for _, extra := range secGoods[1:] {
						logging("Ignoring extra CSAF entry in security.txt: %s", extra.URL)
					}
				} else {
					// Complaint about not matching.
					logging("First entry of security.txt and well-known don't match.")
					// List all the security urls.
					for _, sec := range secGoods {
						logging("Ignoring CSAF entry in security.txt: %s", sec.URL)
					}
				}
				// Take the good well-known.
				return wellknownGood
			}

			// Don't have well-known. Take first good from security.txt.
			// Mention extra CSAF entries
			for _, extra := range secGoods[1:] {
				logging("Ignoring extra CSAF entry in security.txt: %s", extra.URL)
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
	dnsResult := LoadProviderMetadata(client, dnsURL)

	if dnsResult == nil {
		logging("%s not found.", dnsURL)
	} else if len(dnsResult.Messages) > 0 {
		for _, msg := range dnsResult.Messages {
			logging(msg)
		}
	} else {
		// DNS seems to be okay.
		return dnsResult
	}

	// We failed all.
	return nil
}
