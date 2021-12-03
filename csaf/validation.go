package csaf

import (
	"context"
	_ "embed"
	"encoding/json"
	"sort"
	"strings"

	"github.com/qri-io/jsonschema"
)

//go:embed schema/csaf_json_schema.json
var schema []byte

// ValidateCSAF validates the document data against the JSON schema
// of CSAF.
func ValidateCSAF(doc interface{}) ([]string, error) {

	ctx := context.Background()

	rs := &jsonschema.Schema{}
	if err := json.Unmarshal(schema, rs); err != nil {
		return nil, err
	}

	vs := rs.Validate(ctx, doc)
	errs := *vs.Errs

	sort.Slice(errs, func(i, j int) bool {
		pi := errs[i].PropertyPath
		pj := errs[j].PropertyPath
		if strings.HasPrefix(pj, pi) {
			return true
		}
		if strings.HasPrefix(pi, pj) {
			return false
		}
		if pi != pj {
			return pi < pj
		}
		return errs[i].Message < errs[j].Message
	})

	res := make([]string, len(errs))
	for i, e := range errs {
		res[i] = e.PropertyPath + ": " + e.Message
	}

	return res, nil
}
