//go:build ignore

// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"go/format"
	"log"
	"os"
	"sort"
	"strings"
	"text/template"
)

const tmplText = `// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>
//
// THIS FILE IS MACHINE GENERATED. EDIT WITH CARE!

package csaf

{{ range $key := .Keys }}
{{ $def := index $.Definitions $key }}
// {{ $type := printf "%s%s" $.Prefix (typename $key) }}{{ $type }} represents the {{ $key }} in {{ $.Prefix }}.
type {{ $type }} string
const (
	{{ range $enum := $def.Enum -}}
	// {{ $type}}{{ symbol $enum }} is a constant for "{{ $enum }}".
	{{ $type }}{{ symbol $enum }} {{ $type }} = "{{ $enum }}"
	{{ end }}
)
var {{ tolower $.Prefix }}{{ typename $key }}Pattern = alternativesUnmarshal(
	{{ range $enum := $def.Enum -}}
	string({{ $type }}{{ symbol $enum }}),
	{{ end }}
)

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (e *{{ $type }}) UnmarshalText(data []byte) error {
	s, err := {{ tolower $.Prefix }}{{ typename $key }}Pattern(data)
	if err == nil {
		*e = {{ $type }}(s)
	}
	return err
}
{{ end }}
`

var tmpl = template.Must(template.New("enums").Funcs(funcs).Parse(tmplText))

type definition struct {
	Type string   `json:"type"`
	Enum []string `json:"enum"`
}

type schema struct {
	Definitions map[string]*definition `json:"definitions"`
}

var funcs = template.FuncMap{
	"tolower": strings.ToLower,
	"symbol": func(s string) string {
		s = strings.ToLower(s)
		s = strings.ReplaceAll(s, "_", " ")
		s = strings.Title(s)
		s = strings.ReplaceAll(s, " ", "")
		return s
	},
	"typename": func(s string) string {
		if strings.HasSuffix(s, "Type") {
			s = s[:len(s)-len("Type")]
		}
		s = strings.Title(s)
		return s
	},
}

func loadSchema(filename string) (*schema, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var s schema
	if err := json.NewDecoder(f).Decode(&s); err != nil {
		return nil, err
	}
	return &s, nil
}

func check(err error) {
	if err != nil {
		log.Fatalf("error: %v\n", err)
	}
}

func main() {
	var (
		input  = flag.String("i", "input", "")
		output = flag.String("o", "output", "")
		prefix = flag.String("p", "prefix", "")
	)
	flag.Parse()
	if *input == "" {
		log.Fatalln("missing schema")
	}
	if *output == "" {
		log.Fatalln("missing output")
	}
	if *prefix == "" {
		log.Fatalln("missing prefix")
	}

	s, err := loadSchema(*input)
	check(err)

	defs := make([]string, 0, len(s.Definitions))
	for k, v := range s.Definitions {
		if v.Type == "string" && len(v.Enum) > 0 {
			defs = append(defs, k)
		}
	}
	sort.Strings(defs)

	var source bytes.Buffer

	check(tmpl.Execute(&source, map[string]any{
		"Prefix":      *prefix,
		"Definitions": s.Definitions,
		"Keys":        defs,
	}))

	formatted, err := format.Source(source.Bytes())
	check(err)

	check(os.WriteFile(*output, formatted, 0644))
}
