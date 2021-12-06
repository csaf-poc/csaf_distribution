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

var (
	compileSchemaOnce sync.Once
	compileError      error
	compiledSchema    *jsonschema.Schema
)

func compileSchema() {
	c := jsonschema.NewCompiler()

	for _, s := range []struct {
		url  string
		data []byte
	}{
		{"https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json", csafSchema},
		{"https://www.first.org/cvss/cvss-v2.0.json", cvss20},
		{"https://www.first.org/cvss/cvss-v3.0.json", cvss30},
		{"https://www.first.org/cvss/cvss-v3.1.json", cvss31},
	} {
		if compileError = c.AddResource(s.url, bytes.NewReader(s.data)); compileError != nil {
			return
		}
	}

	compiledSchema, compileError = c.Compile(
		"https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json")
}

// ValidateCSAF validates the document data against the JSON schema
// of CSAF.
func ValidateCSAF(doc interface{}) ([]string, error) {

	compileSchemaOnce.Do(compileSchema)
	if compileError != nil {
		return nil, compileError
	}

	err := compiledSchema.Validate(doc)
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
		if e := &errs[i]; e.InstanceLocation != "" && e.Error != "" {
			res = append(res, e.InstanceLocation+": "+e.Error)
		}
	}

	return res, nil
}
