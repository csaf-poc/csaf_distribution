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
	"crypto/tls"
	_ "embed" // Used for embedding.
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/csaf-poc/csaf_distribution/util"
	"github.com/jessevdk/go-flags"
)

//go:embed tmpl/report.html
var reportHTML string

type options struct {
	Output      string      `short:"o" long:"output" description:"File name of the generated report" value-name:"REPORT-FILE"`
	Format      string      `short:"f" long:"format" choice:"json" choice:"html" description:"Format of report" default:"json"`
	Insecure    bool        `long:"insecure" description:"Do not check TLS certificates from provider"`
	ClientCert  *string     `long:"client-cert" description:"TLS client certificate file (PEM encoded data)" value-name:"CERT-FILE"`
	ClientKey   *string     `long:"client-key" description:"TLS client private key file (PEM encoded data)" value-name:"KEY-FILE"`
	Version     bool        `long:"version" description:"Display version of the binary"`
	Verbose     bool        `long:"verbose" short:"v" description:"Verbose output"`
	Rate        *float64    `long:"rate" short:"r" description:"The average upper limit of https operations per second (defaults to unlimited)"`
	Years       *uint       `long:"years" short:"y" description:"Number of years to look back from now" value-name:"YEARS"`
	ExtraHeader http.Header `long:"header" short:"H" description:"One or more extra HTTP header fields"`

	RemoteValidator        string   `long:"validator" description:"URL to validate documents remotely" value-name:"URL"`
	RemoteValidatorCache   string   `long:"validatorcache" description:"FILE to cache remote validations" value-name:"FILE"`
	RemoteValidatorPresets []string `long:"validatorpreset" description:"One or more presets to validate remotely" default:"mandatory"`

	clientCerts []tls.Certificate
}

func errCheck(err error) {
	if err != nil {
		if flags.WroteHelp(err) {
			os.Exit(0)
		}
		log.Fatalf("error: %v\n", err)
	}
}

func (o *options) prepare() error {
	// Load client certs.
	switch hasCert, hasKey := o.ClientCert != nil, o.ClientKey != nil; {

	case hasCert && !hasKey || !hasCert && hasKey:
		return errors.New("both client-key and client-cert options must be set for the authentication")

	case hasCert:
		cert, err := tls.LoadX509KeyPair(*o.ClientCert, *o.ClientKey)
		if err != nil {
			return err
		}
		o.clientCerts = []tls.Certificate{cert}
	}
	return nil
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

// run uses a processor to check all the given domains or direct urls
// and generates a report.
func run(opts *options, domains []string) (*Report, error) {
	p, err := newProcessor(opts)
	if err != nil {
		return nil, err
	}
	defer p.close()
	return p.run(domains)
}

func main() {
	opts := new(options)

	parser := flags.NewParser(opts, flags.Default)
	parser.Usage = "[OPTIONS] domain..."
	domains, err := parser.Parse()
	errCheck(err)

	if opts.Version {
		fmt.Println(util.SemVersion)
		return
	}

	errCheck(opts.prepare())

	if len(domains) == 0 {
		log.Println("No domain or direct url given.")
		return
	}

	report, err := run(opts, domains)
	errCheck(err)

	errCheck(writeReport(report, opts))
}
