// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package csaf

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	bolt "go.etcd.io/bbolt"
)

// defaultURL is default URL where to look for
// the validation service.
const (
	defaultURL     = "http://localhost:3000"
	validationPath = "/api/v1/validate"
)

// defaultPresets are the presets to check.
var defaultPresets = []string{"mandatory"}

var (
	validationsBucket = []byte("validations")
	validFalse        = []byte{0}
	validTrue         = []byte{1}
)

// RemoteValidatorOptions are the configuation options
// the remote validation service.
type RemoteValidatorOptions struct {
	URL     string   `json:"url" toml:"url"`
	Presets []string `json:"presets" toml:"presets"`
	Cache   string   `json:"cache" toml:"cache"`
}

type test struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

// outDocument is the document send to the remote validation service.
type outDocument struct {
	Tests    []test      `json:"tests"`
	Document interface{} `json:"document"`
}

// inDocument is the document recieved from the remote validation service.
type inDocument struct {
	Valid bool `json:"isValid"`
}

var errNotFound = errors.New("not found")

type cache interface {
	get(key []byte) (bool, error)
	set(key []byte, valid bool) error
	Close() error
}

// RemoteValidator validates an advisory document remotely.
type RemoteValidator interface {
	Validate(doc interface{}) (bool, error)
	Close() error
}

// SynchronizedRemoteValidator returns a serialized variant
// of the given remote validator.
func SynchronizedRemoteValidator(validator RemoteValidator) RemoteValidator {
	return &syncedRemoteValidator{RemoteValidator: validator}
}

// remoteValidator is an implementation of an RemoteValidator.
type remoteValidator struct {
	url   string
	tests []test
	cache cache
}

// syncedRemoteValidator is a serialized variant of a remote validator.
type syncedRemoteValidator struct {
	sync.Mutex
	RemoteValidator
}

// Validate implements the validation part of the RemoteValidator interface.
func (srv *syncedRemoteValidator) Validate(doc interface{}) (bool, error) {
	srv.Lock()
	defer srv.Unlock()
	return srv.RemoteValidator.Validate(doc)
}

// Validate implements the closing part of the RemoteValidator interface.
func (srv *syncedRemoteValidator) Close() error {
	srv.Lock()
	defer srv.Unlock()
	return srv.RemoteValidator.Close()
}

// prepareTests precompiles the presets for the remote check.
func prepareTests(presets []string) []test {
	if len(presets) == 0 {
		presets = defaultPresets
	}
	tests := make([]test, len(presets))
	for i := range tests {
		tests[i] = test{Type: "preset", Name: presets[i]}
	}
	return tests
}

// prepareURL prepares the URL to be called for validation.
func prepareURL(url string) string {
	if url == "" {
		return defaultURL + validationPath
	}
	return url + validationPath
}

// prepareCache sets up the cache if it is configured.
func prepareCache(config string) (cache, error) {
	if config == "" {
		return nil, nil
	}

	db, err := bolt.Open(config, 0600, nil)
	if err != nil {
		return nil, err
	}

	// Create the bucket.
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(validationsBucket)
		return err
	}); err != nil {
		db.Close()
		return nil, err
	}

	return boltCache{db}, nil
}

// boltCache is cache implementation based on the bolt datastore.
type boltCache struct{ *bolt.DB }

// get implements the fetch part of the cache interface.
func (bc boltCache) get(key []byte) (valid bool, err error) {
	err2 := bc.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(validationsBucket)
		v := b.Get(key)
		if v == nil {
			err = errNotFound
		} else {
			valid = v[0] != 0
		}
		return nil
	})
	if err2 != nil {
		err = err2
	}
	return
}

// get implements the store part of the cache interface.
func (bc boltCache) set(key []byte, valid bool) error {
	return bc.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(validationsBucket)
		if valid {
			return b.Put(key, validTrue)
		}
		return b.Put(key, validFalse)
	})
}

// Open opens a new remoteValidator.
func (rvo *RemoteValidatorOptions) Open() (RemoteValidator, error) {
	cache, err := prepareCache(rvo.Cache)
	if err != nil {
		return nil, err
	}
	return &remoteValidator{
		url:   prepareURL(rvo.URL),
		tests: prepareTests(rvo.Presets),
		cache: cache,
	}, nil
}

// Close closes the remote validator.
func (v *remoteValidator) Close() error {
	if v.cache != nil {
		return v.cache.Close()
	}
	return nil
}

// key calculates the key for an advisory document and presets.
func (v *remoteValidator) key(doc interface{}) ([]byte, error) {
	h := sha256.New()
	if err := json.NewEncoder(h).Encode(doc); err != nil {
		return nil, err
	}
	for i := range v.tests {
		if _, err := h.Write([]byte(v.tests[i].Name)); err != nil {
			return nil, err
		}
	}
	return h.Sum(nil), nil
}

// Validate executes a remote validation of an advisory.
func (v *remoteValidator) Validate(doc interface{}) (bool, error) {

	var key []byte

	if v.cache != nil {
		var err error
		if key, err = v.key(doc); err != nil {
			return false, err
		}
		valid, err := v.cache.get(key)
		if err != errNotFound {
			if err != nil {
				return false, err
			}
			return valid, nil
		}
	}

	o := outDocument{
		Document: doc,
		Tests:    v.tests,
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(&o); err != nil {
		return false, err
	}

	resp, err := http.Post(
		v.url,
		"application/json",
		bytes.NewReader(buf.Bytes()))

	if err != nil {
		return false, err
	}

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf(
			"POST failed: %s (%d)", resp.Status, resp.StatusCode)
	}

	valid, err := func() (bool, error) {
		defer resp.Body.Close()
		var in inDocument
		return in.Valid, json.NewDecoder(resp.Body).Decode(&in)
	}()

	if err != nil {
		return false, err
	}

	if key != nil {
		// store in cache
		if err := v.cache.set(key, valid); err != nil {
			return valid, err
		}
	}

	return valid, nil
}
