// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

// Package main implements the csaf_downloader tool.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"

	"github.com/csaf-poc/csaf_distribution/v2/util"
	"github.com/jessevdk/go-flags"
)

const defaultWorker = 2

type options struct {
	Directory            *string  `short:"d" long:"directory" description:"DIRectory to store the downloaded files in" value-name:"DIR"`
	Insecure             bool     `long:"insecure" description:"Do not check TLS certificates from provider"`
	IgnoreSignatureCheck bool     `long:"ignoresigcheck" description:"Ignore signature check results, just warn on mismatch"`
	Version              bool     `long:"version" description:"Display version of the binary"`
	Verbose              bool     `long:"verbose" short:"v" description:"Verbose output"`
	Rate                 *float64 `long:"rate" short:"r" description:"The average upper limit of https operations per second (defaults to unlimited)"`
	Worker               int      `long:"worker" short:"w" description:"NUMber of concurrent downloads" value-name:"NUM"`

	ExtraHeader http.Header `long:"header" short:"H" description:"One or more extra HTTP header fields"`

	RemoteValidator        string   `long:"validator" description:"URL to validate documents remotely" value-name:"URL"`
	RemoteValidatorCache   string   `long:"validatorcache" description:"FILE to cache remote validations" value-name:"FILE"`
	RemoteValidatorPresets []string `long:"validatorpreset" description:"One or more presets to validate remotely" default:"mandatory"`
}

func errCheck(err error) {
	if err != nil {
		if flags.WroteHelp(err) {
			os.Exit(0)
		}
		log.Fatalf("error: %v\n", err)
	}
}

func run(opts *options, domains []string) error {
	d, err := newDownloader(opts)
	if err != nil {
		return err
	}
	defer d.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	return d.run(ctx, domains)
}

func main() {

	opts := &options{
		Worker: defaultWorker,
	}

	parser := flags.NewParser(opts, flags.Default)
	parser.Usage = "[OPTIONS] domain..."
	domains, err := parser.Parse()
	errCheck(err)

	if opts.Version {
		fmt.Println(util.SemVersion)
		return
	}

	if len(domains) == 0 {
		log.Println("No domains given.")
		return
	}

	errCheck(run(opts, domains))
}
