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
	Output     string  `short:"o" long:"output" description:"File name of the generated report" value-name:"REPORT-FILE"`
	Format     string  `short:"f" long:"format" choice:"json" choice:"html" description:"Format of report" default:"json"`
	Insecure   bool    `long:"insecure" description:"Do not check TLS certificates from provider"`
	ClientCert *string `long:"client-cert" description:"TLS client certificate file (PEM encoded data)" value-name:"CERT-FILE"`
	ClientKey  *string `long:"client-key" description:"TLS client private key file (PEM encoded data)" value-name:"KEY-FILE"`
}

func errCheck(err error) {
	if err != nil {
		if e, ok := err.(*flags.Error); ok && e.Type == flags.ErrHelp {
			os.Exit(0)
		}
		log.Fatalf("error: %v\n", err)
	}
}

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

// buildReporters initializes each report by assigning a number and description to it.
// It returns an array of the reporter interface type.
func buildReporters() []reporter {
	return []reporter{
		&tlsReporter{baseReporter{num: 3, description: "TLS"}},
		&redirectsReporter{baseReporter{num: 6, description: "Redirects"}},
		&providerMetadataReport{baseReporter{num: 7, description: "provider-metadata.json"}},
		&securityReporter{baseReporter{num: 8, description: "security.txt"}},
		&wellknownMetadataReporter{baseReporter{num: 9, description: "/.well-known/csaf/provider-metadata.json"}},
		&dnsPathReporter{baseReporter{num: 10, description: "DNS path"}},
		&oneFolderPerYearReport{baseReporter{num: 11, description: "One folder per year"}},
		&indexReporter{baseReporter{num: 12, description: "index.txt"}},
		&changesReporter{baseReporter{num: 13, description: "changes.csv"}},
		&directoryListingsReporter{baseReporter{num: 14, description: "Directory listings"}},
		&integrityReporter{baseReporter{num: 18, description: "Integrity"}},
		&signaturesReporter{baseReporter{num: 19, description: "Signatures"}},
		&publicPGPKeyReporter{baseReporter{num: 20, description: "Public OpenPGP Key"}},
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

	if (opts.ClientCert != nil && opts.ClientKey == nil) || (opts.ClientCert == nil && opts.ClientKey != nil) {
		log.Println("Both client-key and client-cert options must be set for the authentication.")
		return
	}

	p := newProcessor(opts)

	report, err := p.run(buildReporters(), domains)
	errCheck(err)

	errCheck(writeReport(report, opts))
}
