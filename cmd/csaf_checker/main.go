// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

// Package main implements the csaf_checker tool.
package main

import (
	"bufio"
	_ "embed" // Used for embedding.
	"encoding/json"
	"html/template"
	"io"
	"log"
	"os"
)

//go:embed tmpl/report.html
var reportHTML string

// writeJSON writes the JSON encoding of the given report to the given stream.
// It returns nil, otherwise an error.
func writeJSON(report *Report, w io.WriteCloser) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	err := enc.Encode(report)
	if e := w.Close(); err != nil {
		err = e
	}
	return err
}

// writeHTML writes the given report to the given writer, it uses the template
// in the "reportHTML" variable. It returns nil, otherwise an error.
func writeHTML(report *Report, w io.WriteCloser) error {
	tmpl, err := template.New("Report HTML").Parse(reportHTML)
	if err != nil {
		w.Close()
		return err
	}
	buf := bufio.NewWriter(w)

	if err := tmpl.Execute(buf, report); err != nil {
		w.Close()
		return err
	}

	err = buf.Flush()
	if e := w.Close(); err == nil {
		err = e
	}
	return err
}

type nopCloser struct{ io.Writer }

func (nc *nopCloser) Close() error { return nil }

// writeReport defines where to write the report according to the "output" flag option.
// It calls also the "writeJSON" or "writeHTML" function according to the "format" flag option.
func writeReport(report *Report, cfg *config) error {

	var w io.WriteCloser

	if cfg.Output == "" {
		w = &nopCloser{os.Stdout}
	} else {
		f, err := os.Create(cfg.Output)
		if err != nil {
			return err
		}
		w = f
	}

	var writer func(*Report, io.WriteCloser) error

	switch cfg.Format {
	case "json":
		writer = writeJSON
	default:
		writer = writeHTML
	}

	return writer(report, w)
}

// run uses a processor to check all the given domains or direct urls
// and generates a report.
func run(cfg *config, domains []string) (*Report, error) {
	p, err := newProcessor(cfg)
	if err != nil {
		return nil, err
	}
	defer p.close()
	return p.run(domains)
}

func main() {
	domains, cfg, err := parseArgsConfig()

	errCheck(cfg.prepare())

	if len(domains) == 0 {
		log.Println("No domain or direct url given.")
		return
	}

	report, err := run(cfg, domains)
	errCheck(err)

	errCheck(writeReport(report, cfg))
}
