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
	Config  string `short:"c" long:"config" description:"File name of the configuration file" value-name:"CFG-FILE" default:"aggregator.toml"`
	Version bool   `long:"version" description:"Display version of the binary"`
}

func errCheck(err error) {
	if err != nil {
		if e, ok := err.(*flags.Error); ok && e.Type == flags.ErrHelp {
			os.Exit(0)
		}
		log.Fatalf("error: %v\n", err)
	}
}

func main() {
	opts := new(options)

	_, err := flags.Parse(opts)
	errCheck(err)

	if opts.Version {
		fmt.Println(util.SemVersion)
		return
	}

	cfg, err := loadConfig(opts.Config)
	errCheck(err)

	p := processor{cfg: cfg}
	errCheck(p.process())
}
