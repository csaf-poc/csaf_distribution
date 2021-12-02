package csaf

import (
	_ "embed"

	"github.com/xeipuuv/gojsonschema"
)

//go:embed schema/csaf_json_schema.json
var schema string

// Validate validates the document data against the JSON schema
// of CSAF.
func Validate(data []byte) ([]string, error) {
	schemaLoader := gojsonschema.NewStringLoader(schema)
	documentLoader := gojsonschema.NewStringLoader(string(data))

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return nil, err
	}

	if result.Valid() {
		return nil, nil
	}

	errors := result.Errors()
	res := make([]string, len(errors))
	for i, e := range errors {
		res[i] = e.String()
	}

	return res, nil
}
