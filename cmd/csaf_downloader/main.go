// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/csaf-poc/csaf_distribution/util"
	"github.com/jessevdk/go-flags"
)

type options struct {
	Directory *string  `short:"d" long:"directory" description:"Directory to store the downloaded files in"`
	Insecure  bool     `long:"insecure" description:"Do not check TLS certificates from provider"`
	Version   bool     `long:"version" description:"Display version of the binary"`
	Verbose   bool     `long:"verbose" short:"v" description:"Verbose output"`
	Rate      *float64 `long:"rate" short:"r" description:"The average upper limit of https operations per second"`
}

func errCheck(err error) {
	if err != nil {
		if flags.WroteHelp(err) {
			os.Exit(0)
		}
		log.Fatalf("error: %v\n", err)
	}
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

	if len(domains) == 0 {
		log.Println("No domains given.")
		return
	}

	d := newDownloader(opts)

	errCheck(d.run(domains))
}
