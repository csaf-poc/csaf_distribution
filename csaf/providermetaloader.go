// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package csaf

import (
	"errors"
	"log"
	"strings"

	"github.com/csaf-poc/csaf_distribution/util"
)

// ProviderMetadataLoader helps load provider-metadata.json from
// the various locations.
type ProviderMetadataLoader struct {
	client  *util.Client
	logging func(string, ...any)
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
)

// ProviderMetadataLoadMessage is a message generated while loading
// a provider meta data file.
type ProviderMetadataLoadMessage struct {
	Type    ProviderMetadataLoadMessageType
	Message string
}

// LoadedProviderMetadata represents a loaded provider metadata.
type LoadedProviderMetadata struct {
	// URL is location where the document was found.
	URL string
	// Document is the de-serialized JSON document.
	Document any
	// Hash is a SHA256 sum over the document.
	Hash []byte
	// Messages are the error message happened while loading.
	Messages []ProviderMetadataLoadMessage
}

// Valid returns true if the loaded document is valid.
func (lpm *LoadedProviderMetadata) Valid() bool {
	return lpm != nil && lpm.Document != nil && lpm.Hash != nil
}

// NewProviderMetadataLoader create a new loader.
func NewProviderMetadataLoader(
	client *util.Client,
	logging func(string, ...any),
) *ProviderMetadataLoader {

	// If no logging was given log to stdout.
	if logging == nil {
		logging = func(format string, args ...any) {
			log.Printf("ProviderMetadataLoader: "+format+"\n", args...)
		}
	}
	return &ProviderMetadataLoader{
		client:  client,
		logging: logging,
	}
}

// Load loads a provider metadata for a given path.
// If the domain starts with `https://` it only attemps to load
// the data from that URL.
func (pmdl *ProviderMetadataLoader) Load(path string) (*LoadedProviderMetadata, error) {

	// check direct path
	if strings.HasPrefix(path, "https://") {
		return pmdl.loadFromURL(path)
	}

	// TODO: Implement me!
	return nil, errors.New("not implemented, yet")
}

// loadFromURL loads a provider metadata from a given URL.
func (pmdl *ProviderMetadataLoader) loadFromURL(path string) (*LoadedProviderMetadata, error) {

	_ = path

	// TODO: Implement me!
	return nil, errors.New("not implemented, yet")
}
