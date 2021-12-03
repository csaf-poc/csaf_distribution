package csaf

import (
	"context"
	_ "embed"
	"encoding/json"
	"log"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/qri-io/jsonschema"
)

//go:embed schema/csaf_json_schema.json
var schema []byte

//go:embed schema/cvss-v2.0.json
var cvss20 []byte

//go:embed schema/cvss-v3.0.json
var cvss30 []byte

//go:embed schema/cvss-v3.1.json
var cvss31 []byte

func embedLoader(ctx context.Context, uri *url.URL, schema *jsonschema.Schema) error {

	var data []byte
	switch u := uri.String(); u {
	case "https://www.first.org/cvss/cvss-v2.0.json":
		data = cvss20
	case "https://www.first.org/cvss/cvss-v3.0.json":
		data = cvss30
	case "https://www.first.org/cvss/cvss-v3.1.json":
		data = cvss31
	default:
		log.Printf("escaped schema loader: %s\n", u)
		return jsonschema.HTTPSchemaLoader(ctx, uri, schema)
	}
	if schema == nil {
		schema = &jsonschema.Schema{}
	}
	return json.Unmarshal(data, schema)
}

var registerEmbedLoaderOnce sync.Once

func registerEmbedLoader() {
	// Hook into schema loading.
	slr := jsonschema.GetSchemaLoaderRegistry()
	slr.Register("https", embedLoader)
}

// ValidateCSAF validates the document data against the JSON schema
// of CSAF.
func ValidateCSAF(doc interface{}) ([]string, error) {

	registerEmbedLoaderOnce.Do(registerEmbedLoader)

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
