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

var (
	compiledCSAFSchema     compiledSchema
	compiledProviderSchema compiledSchema
)

func init() {
	compiledCSAFSchema.compiler([]schemaData{
		{"https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json", csafSchema},
		{"https://www.first.org/cvss/cvss-v2.0.json", cvss20},
		{"https://www.first.org/cvss/cvss-v3.0.json", cvss30},
		{"https://www.first.org/cvss/cvss-v3.1.json", cvss31},
	})
	compiledProviderSchema.compiler([]schemaData{
		{"https://docs.oasis-open.org/csaf/csaf/v2.0/provider_json_schema.json", providerSchema},
		{"https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json", csafSchema},
	})
}

type schemaData struct {
	url  string
	data []byte
}

type compiledSchema struct {
	once     sync.Once
	compile  func()
	err      error
	compiled *jsonschema.Schema
}

func (cs *compiledSchema) compiler(sds []schemaData) {
	if len(sds) == 0 {
		panic("missing schema data")
	}
	cs.compile = func() {
		c := jsonschema.NewCompiler()
		for _, s := range sds {
			if cs.err = c.AddResource(
				s.url, bytes.NewReader(s.data)); cs.err != nil {
				return
			}
		}
		cs.compiled, cs.err = c.Compile(sds[0].url)
	}
}

func (cs *compiledSchema) validate(doc interface{}) ([]string, error) {
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
func ValidateCSAF(doc interface{}) ([]string, error) {
	return compiledCSAFSchema.validate(doc)
}

// ValidateProviderMetadata validates the document doc against the JSON schema
// of provider metadata.
func ValidateProviderMetadata(doc interface{}) ([]string, error) {
	return compiledProviderSchema.validate(doc)
}
