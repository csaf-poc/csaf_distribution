// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package csaf

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/csaf-poc/csaf_distribution/v3/util"
)

// ProviderMetadataLoader helps load provider-metadata.json from
// the various locations.
type ProviderMetadataLoader struct {
	client   util.Client
	already  map[string]*LoadedProviderMetadata
	messages ProviderMetadataLoadMessages
}

// ProviderMetadataLoadMessageType is the type of the message.
type ProviderMetadataLoadMessageType int

const (
	//JSONDecodingFailed indicates problems with JSON decoding
	JSONDecodingFailed ProviderMetadataLoadMessageType = iota
	// SchemaValidationFailed indicates a general problem with schema validation.
	SchemaValidationFailed
	// SchemaValidationFailedDetail is a failure detail in schema validation.
	SchemaValidationFailedDetail
	// HTTPFailed indicates that loading on HTTP level failed.
	HTTPFailed
	// ExtraProviderMetadataFound indicates an extra PMD found in security.txt.
	ExtraProviderMetadataFound
	// WellknownSecurityMismatch indicates that the PMDs found under wellknown and
	// in the security do not match.
	WellknownSecurityMismatch
	// IgnoreProviderMetadata indicates that a extra PMD was ignored.
	IgnoreProviderMetadata
)

// ProviderMetadataLoadMessage is a message generated while loading
// a provider meta data file.
type ProviderMetadataLoadMessage struct {
	Type    ProviderMetadataLoadMessageType
	Message string
}

// ProviderMetadataLoadMessages is a list of loading messages.
type ProviderMetadataLoadMessages []ProviderMetadataLoadMessage

// LoadedProviderMetadata represents a loaded provider metadata.
type LoadedProviderMetadata struct {
	// URL is location where the document was found.
	URL string
	// Document is the de-serialized JSON document.
	Document any
	// Hash is a SHA256 sum over the document.
	Hash []byte
	// Messages are the error message happened while loading.
	Messages ProviderMetadataLoadMessages
}

// Add appends a message to the list of loading messages.
func (pmlm *ProviderMetadataLoadMessages) Add(
	typ ProviderMetadataLoadMessageType,
	msg string,
) {
	*pmlm = append(*pmlm, ProviderMetadataLoadMessage{
		Type:    typ,
		Message: msg,
	})
}

// AppendUnique appends unique messages from a second list.
func (pmlm *ProviderMetadataLoadMessages) AppendUnique(other ProviderMetadataLoadMessages) {
next:
	for _, o := range other {
		for _, m := range *pmlm {
			if m == o {
				continue next
			}
		}
		*pmlm = append(*pmlm, o)
	}
}

// Valid returns true if the loaded document is valid.
func (lpm *LoadedProviderMetadata) Valid() bool {
	return lpm != nil && lpm.Document != nil && lpm.Hash != nil
}

// NewProviderMetadataLoader create a new loader.
func NewProviderMetadataLoader(client util.Client) *ProviderMetadataLoader {
	return &ProviderMetadataLoader{
		client:  client,
		already: map[string]*LoadedProviderMetadata{},
	}
}

// Load loads a provider metadata for a given path.
// If the domain starts with `https://` it only attemps to load
// the data from that URL.
func (pmdl *ProviderMetadataLoader) Load(domain string) *LoadedProviderMetadata {

	// Check direct path
	if strings.HasPrefix(domain, "https://") {
		return pmdl.loadFromURL(domain)
	}

	// First try the well-known path.
	wellknownURL := "https://" + domain + "/.well-known/csaf/provider-metadata.json"

	wellknownResult := pmdl.loadFromURL(wellknownURL)

	// Valid provider metadata under well-known.
	var wellknownGood *LoadedProviderMetadata

	// We have a candidate.
	if wellknownResult.Valid() {
		wellknownGood = wellknownResult
	}

	// Next load the PMDs from security.txt
	secResults := pmdl.loadFromSecurity(domain)

	// Filter out the results which are valid.
	var secGoods []*LoadedProviderMetadata

	for _, result := range secResults {
		if len(result.Messages) > 0 {
			// If there where validation issues append them
			// to the overall report
			pmdl.messages.AppendUnique(pmdl.messages)
		} else {
			secGoods = append(secGoods, result)
		}
	}

	// Mention extra CSAF entries in security.txt.
	ignoreExtras := func() {
		for _, extra := range secGoods[1:] {
			pmdl.messages.Add(
				ExtraProviderMetadataFound,
				fmt.Sprintf("Ignoring extra CSAF entry in security.txt: %s", extra.URL))
		}
	}

	// security.txt contains good entries.
	if len(secGoods) > 0 {
		// we already have a good wellknown, take it.
		if wellknownGood != nil {
			// check if first of security urls is identical to wellknown.
			if bytes.Equal(wellknownGood.Hash, secGoods[0].Hash) {
				ignoreExtras()
			} else {
				// Complaint about not matching.
				pmdl.messages.Add(
					WellknownSecurityMismatch,
					"First entry of security.txt and well-known don't match.")
				// List all the security urls.
				for _, sec := range secGoods {
					pmdl.messages.Add(
						IgnoreProviderMetadata,
						fmt.Sprintf("Ignoring CSAF entry in security.txt: %s", sec.URL))
				}
			}
			// Take the good well-known.
			wellknownGood.Messages.AppendUnique(pmdl.messages)
			return wellknownGood
		}

		// Don't have well-known. Take first good from security.txt.
		ignoreExtras()
		secGoods[0].Messages.AppendUnique(pmdl.messages)
		return secGoods[0]
	}

	// If we have a good well-known take it.
	if wellknownGood != nil {
		wellknownGood.Messages.AppendUnique(pmdl.messages)
		return wellknownGood
	}

	// Last resort: fall back to DNS.
	dnsURL := "https://csaf.data.security." + domain
	return pmdl.loadFromURL(dnsURL)
}

// loadFromSecurity loads the PMDs mentioned in the security.txt.
func (pmdl *ProviderMetadataLoader) loadFromSecurity(domain string) []*LoadedProviderMetadata {

	// If .well-known fails try legacy location.
	for _, path := range []string{
		"https://" + domain + "/.well-known/security.txt",
		"https://" + domain + "/security.txt",
	} {
		res, err := pmdl.client.Get(path)
		if err != nil {
			pmdl.messages.Add(
				HTTPFailed,
				fmt.Sprintf("Fetching %q failed: %v", path, err))
			continue
		}
		if res.StatusCode != http.StatusOK {
			pmdl.messages.Add(
				HTTPFailed,
				fmt.Sprintf("Fetching %q failed: %s (%d)", path, res.Status, res.StatusCode))
			continue
		}

		// Extract all potential URLs from CSAF.
		urls, err := func() ([]string, error) {
			defer res.Body.Close()
			return ExtractProviderURL(res.Body, true)
		}()

		if err != nil {
			pmdl.messages.Add(
				HTTPFailed,
				fmt.Sprintf("Loading %q failed: %v", path, err))
			continue
		}

		var loaded []*LoadedProviderMetadata

		// Load the URLs
	nextURL:
		for _, url := range urls {
			lpmd := pmdl.loadFromURL(url)
			// If loading failed note it down.
			if !lpmd.Valid() {
				pmdl.messages.AppendUnique(lpmd.Messages)
				continue
			}
			// Check for duplicates
			for _, l := range loaded {
				if l == lpmd {
					continue nextURL
				}
			}
			loaded = append(loaded, lpmd)
		}

		return loaded
	}
	return nil
}

// loadFromURL loads a provider metadata from a given URL.
func (pmdl *ProviderMetadataLoader) loadFromURL(path string) *LoadedProviderMetadata {

	result := LoadedProviderMetadata{URL: path}

	res, err := pmdl.client.Get(path)
	if err != nil {
		result.Messages.Add(
			HTTPFailed,
			fmt.Sprintf("fetching %q failed: %v", path, err))
		return &result
	}
	if res.StatusCode != http.StatusOK {
		result.Messages.Add(
			HTTPFailed,
			fmt.Sprintf("fetching %q failed: %s (%d)", path, res.Status, res.StatusCode))
		return &result
	}

	// TODO: Check for application/json and log it.

	defer res.Body.Close()

	// Calculate checksum for later comparison.
	hash := sha256.New()

	tee := io.TeeReader(res.Body, hash)

	var doc any

	if err := json.NewDecoder(tee).Decode(&doc); err != nil {
		result.Messages.Add(
			JSONDecodingFailed,
			fmt.Sprintf("JSON decoding failed: %v", err))
		return &result
	}

	// Before checking the err lets check if we had the same
	// document before. If so it will have failed parsing before.

	sum := hash.Sum(nil)
	key := string(sum)

	// If we already have loaded it return the cached result.
	if r := pmdl.already[key]; r != nil {
		return r
	}

	// write it back as loaded

	switch errors, err := ValidateProviderMetadata(doc); {
	case err != nil:
		result.Messages.Add(
			SchemaValidationFailed,
			fmt.Sprintf("%s: Validating against JSON schema failed: %v", path, err))

	case len(errors) > 0:
		result.Messages = []ProviderMetadataLoadMessage{{
			Type:    SchemaValidationFailed,
			Message: fmt.Sprintf("%s: Validating against JSON schema failed: %v", path, err),
		}}
		for _, msg := range errors {
			result.Messages.Add(
				SchemaValidationFailedDetail,
				strings.ReplaceAll(msg, `%`, `%%`))
		}
	default:
		// Only store in result if validation passed.
		result.Document = doc
		result.Hash = sum
	}

	pmdl.already[key] = &result
	return &result
}
