// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package csaf

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/csaf-poc/csaf_distribution/util"
)

// LoadedProviderMetadata represents a loaded provider metadata.
type LoadedProviderMetadata struct {
	// URL is location where the document was found.
	URL string
	// Document is the de-serialized JSON document.
	Document interface{}
	// Hash is a SHA256 sum over the document.
	Hash []byte
	// Messages are the error message happened while loading.
	Messages []string
}

// LoadProviderMetadataFromURL loads a provider metadata from a given URL.
// Returns nil if the document was not found.
func LoadProviderMetadataFromURL(client util.Client, url string) *LoadedProviderMetadata {

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

	errors, err := ValidateProviderMetadata(result.Document)
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

// LoadProviderMetadatasFromSecurity loads a secturity.txt,
// extracts and the CSAF urls from the document.
// Returns nil if no url was successfully found.
func LoadProviderMetadatasFromSecurity(client util.Client, path string) []*LoadedProviderMetadata {

	res, err := client.Get(path)

	if err != nil || res.StatusCode != http.StatusOK {
		// Treat as not found.
		return nil
	}

	// Extract all potential URLs from CSAF.
	urls, err := func() ([]string, error) {
		defer res.Body.Close()
		return ExtractProviderURL(res.Body, true)
	}()

	if err != nil {
		// Treat as not found
		return nil
	}

	var results []*LoadedProviderMetadata

	// Load the URLs
	for _, url := range urls {
		if result := LoadProviderMetadataFromURL(client, url); result != nil {
			results = append(results, result)
		}
	}

	return results
}

// LoadProviderMetadataForDomain loads a provider metadata for a given domain.
// Returns nil if no provider metadata (PMD) was found.
// If the domain starts with `https://` it only attemps to load
// the data from that URL.
// The logging can be used to track the errors happening while loading.
func LoadProviderMetadataForDomain(
	client util.Client,
	domain string,
	logging func(format string, args ...interface{}),
) *LoadedProviderMetadata {

	if logging == nil {
		logging = func(format string, args ...interface{}) {
			log.Printf("FindProviderMetadata: "+format+"\n", args...)
		}
	}

	lg := func(result *LoadedProviderMetadata, url string) {
		if result == nil {
			logging("%s not found.", url)
		} else {
			for _, msg := range result.Messages {
				logging(msg)
			}
		}
	}

	// check direct path
	if strings.HasPrefix(domain, "https://") {
		result := LoadProviderMetadataFromURL(client, domain)
		lg(result, domain)
		return result
	}

	// Valid provider metadata under well-known.
	var wellknownGood *LoadedProviderMetadata

	// First try well-know path
	wellknownURL := "https://" + domain + "/.well-known/csaf/provider-metadata.json"
	wellknownResult := LoadProviderMetadataFromURL(client, wellknownURL)
	lg(wellknownResult, wellknownURL)

	// We have a candidate.
	if wellknownResult != nil {
		wellknownGood = wellknownResult
	}

	// Next load the PMDs from security.txt
	secURL := "https://" + domain + "/.well-known/security.txt"
	secResults := LoadProviderMetadatasFromSecurity(client, secURL)

	if secResults == nil {
		logging("%s failed to load.", secURL)
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

	// Last resort: fall back to DNS.
	dnsURL := "https://csaf.data.security." + domain
	dnsResult := LoadProviderMetadataFromURL(client, dnsURL)

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

// ExtractProviderURL extracts URLs of provider metadata.
// If all is true all URLs are returned. Otherwise only the first is returned.
func ExtractProviderURL(r io.Reader, all bool) ([]string, error) {
	const csaf = "CSAF:"

	var urls []string

	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, csaf) {
			urls = append(urls, strings.TrimSpace(line[len(csaf):]))
			if !all {
				return urls, nil
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return urls, nil
}
