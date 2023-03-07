// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package csaf

import (
	"bytes"
	_ "embed" // Used for embedding.
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

//go:embed schema/csaf_json_schema.json
var csafSchema []byte

//go:embed schema/cvss-v2.0.json
var cvss20 []byte

//go:embed schema/cvss-v3.0.json
var cvss30 []byte

//go:embed schema/cvss-v3.1.json
var cvss31 []byte

//go:embed schema/provider_json_schema.json
var providerSchema []byte

//go:embed schema/aggregator_json_schema.json
var aggregatorSchema []byte

//go:embed schema/ROLIE_feed_json_schema.json
var rolieSchema []byte

var (
	compiledCSAFSchema       compiledSchema
	compiledProviderSchema   compiledSchema
	compiledAggregatorSchema compiledSchema
	compiledRolieSchema      compiledSchema
)

func loadURL(s string) (io.ReadCloser, error) {
	loader := func(data []byte) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	}
	switch s {
	case "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json":
		return loader(csafSchema)
	case "https://www.first.org/cvss/cvss-v2.0.json":
		return loader(cvss20)
	case "https://www.first.org/cvss/cvss-v3.0.json":
		return loader(cvss30)
	case "https://www.first.org/cvss/cvss-v3.1.json":
		return loader(cvss31)
	case "https://docs.oasis-open.org/csaf/csaf/v2.0/provider_json_schema.json":
		return loader(providerSchema)
	case "https://docs.oasis-open.org/csaf/csaf/v2.0/aggregator_json_schema.json":
		return loader(aggregatorSchema)
	case "https://raw.githubusercontent.com/tschmidtb51/csaf/ROLIE-schema/csaf_2.0/json_schema/ROLIE_feed_json_schema.json":
		return loader(rolieSchema)
	default:
		return jsonschema.LoadURL(s)
	}
}

func init() {
	compiledCSAFSchema.compiler(
		"https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json")
	compiledProviderSchema.compiler(
		"https://docs.oasis-open.org/csaf/csaf/v2.0/provider_json_schema.json")
	compiledAggregatorSchema.compiler(
		"https://docs.oasis-open.org/csaf/csaf/v2.0/aggregator_json_schema.json")
	compiledRolieSchema.compiler(
		"https://raw.githubusercontent.com/tschmidtb51/csaf/ROLIE-schema/csaf_2.0/json_schema/ROLIE_feed_json_schema.json")
}

type compiledSchema struct {
	once     sync.Once
	compile  func()
	err      error
	compiled *jsonschema.Schema
}

func (cs *compiledSchema) compiler(url string) {
	cs.compile = func() {
		c := jsonschema.NewCompiler()
		c.LoadURL = loadURL
		cs.compiled, cs.err = c.Compile(url)
	}
}

func (cs *compiledSchema) validate(doc any) ([]string, error) {
	cs.once.Do(cs.compile)

	if cs.err != nil {
		return nil, cs.err
	}

	err := cs.compiled.Validate(doc)
	if err == nil {
		return nil, nil
	}

	valErr, ok := err.(*jsonschema.ValidationError)
	if !ok {
		return nil, err
	}

	basic := valErr.BasicOutput()
	if basic.Valid {
		return nil, nil
	}

	errs := basic.Errors

	sort.Slice(errs, func(i, j int) bool {
		pi := errs[i].InstanceLocation
		pj := errs[j].InstanceLocation
		if strings.HasPrefix(pj, pi) {
			return true
		}
		if strings.HasPrefix(pi, pj) {
			return false
		}
		if pi != pj {
			return pi < pj
		}
		return errs[i].Error < errs[j].Error
	})

	res := make([]string, 0, len(errs))

	for i := range errs {
		e := &errs[i]
		if e.Error == "" {
			continue
		}
		loc := e.InstanceLocation
		if loc == "" {
			loc = e.AbsoluteKeywordLocation
		}
		res = append(res, loc+": "+e.Error)
	}

	return res, nil
}

// ValidateCSAF validates the document doc against the JSON schema
// of CSAF.
func ValidateCSAF(doc any) ([]string, error) {
	return compiledCSAFSchema.validate(doc)
}

// ValidateProviderMetadata validates the document doc against the JSON schema
// of provider metadata.
func ValidateProviderMetadata(doc any) ([]string, error) {
	return compiledProviderSchema.validate(doc)
}

// ValidateAggregator validates the document doc against the JSON schema
// of aggregator.
func ValidateAggregator(doc any) ([]string, error) {
	return compiledAggregatorSchema.validate(doc)
}

// ValidateROLIE validates the ROLIE feed against the JSON schema
// of ROLIE
func ValidateROLIE(doc any) ([]string, error) {
	return compiledRolieSchema.validate(doc)
}
