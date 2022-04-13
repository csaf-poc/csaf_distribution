// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package main

import (
	"fmt"
	"log"
	"net/http/cgi"

	"github.com/csaf-poc/csaf_distribution/util"
	"github.com/jessevdk/go-flags"
)

type options struct {
	Version bool `long:"version" description:"Display version of the binary"`
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("error: %v\n", err)
	}

	var opts options
	parser := flags.NewParser(&opts, flags.Default)
	parser.Parse()
	if opts.Version {
		fmt.Println(util.SemVersion)
		return
	}

	c, err := newController(cfg)
	if err != nil {
		log.Fatalf("error: %v\n", err)
	}
	pim := newPathInfoMux()
	c.bind(pim)

	if err := cgi.Serve(pim); err != nil {
		log.Fatalf("error: %v\n", err)
	}
}
