// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package main

import (
	"bufio"
	_ "embed" // Used for embedding.
	"encoding/json"
	"html/template"
	"io"
	"log"
	"os"

	"github.com/jessevdk/go-flags"
)

//go:embed tmpl/report.html
var reportHTML string

type options struct {
	Output   string `short:"o" long:"output" description:"File name of the generated report" value-name:"REPORT-FILE"`
	Format   string `short:"f" long:"format" choice:"json" choice:"html" description:"Format of report" default:"json"`
	Insecure bool   `long:"insecure" description:"Do not check TSL certificates from provider"`
}

func errCheck(err error) {
	if err != nil {
		if e, ok := err.(*flags.Error); ok && e.Type == flags.ErrHelp {
			os.Exit(0)
		}
		log.Fatalf("error: %v\n", err)
	}
}

func writeJSON(report *Report, w io.WriteCloser) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	err := enc.Encode(report)
	if e := w.Close(); err != nil {
		err = e
	}
	return err
}

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

func writeReport(report *Report, opts *options) error {

	var w io.WriteCloser

	if opts.Output == "" {
		w = &nopCloser{os.Stdout}
	} else {
		f, err := os.Create(opts.Output)
		if err != nil {
			return err
		}
		w = f
	}

	var writer func(*Report, io.WriteCloser) error

	switch opts.Format {
	case "json":
		writer = writeJSON
	default:
		writer = writeHTML
	}

	return writer(report, w)
}

func buildChecks() checks {
	return checks{
		&tlsCheck{baseCheck{3, "TLS"}},
		&redirectsCheck{baseCheck{6, "Redirects"}},
		&providerMetadataCheck{baseCheck{7, "provider-metadata.json"}},
		&securityCheck{baseCheck{8, "security.txt"}},
		&wellknownMetadataCheck{baseCheck{9, "/.well-known/csaf/provider-metadata.json"}},
		&dnsPathCheck{baseCheck{10, "DNS path"}},
		&oneFolderPerYearCheck{baseCheck{11, "One folder per year"}},
		&indexCheck{baseCheck{12, "index.txt"}},
		&changesCheck{baseCheck{13, "changes.csv"}},
		&directoryListingsCheck{baseCheck{14, "Directory listings"}},
		&integrityCheck{baseCheck{18, "Integrity"}},
		&signaturesCheck{baseCheck{19, "Signatures"}},
		&publicPGPKeyCheck{baseCheck{20, "Public PGP Key"}},
	}
}

func main() {
	opts := new(options)

	domains, err := flags.Parse(opts)
	errCheck(err)

	if len(domains) == 0 {
		log.Println("No domains given.")
		return
	}

	report, err := buildChecks().run(domains)
	errCheck(err)

	errCheck(writeReport(report, opts))
}
