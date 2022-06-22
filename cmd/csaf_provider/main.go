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
	"net/http"
	"net/http/cgi"

	"github.com/csaf-poc/csaf_distribution/util"
	"github.com/jessevdk/go-flags"
)

type options struct {
	Version bool `long:"version" description:"Display version of the binary"`
}
var help_message = "The csaf_provider is a cgi binary and is designed to be served via a web server."

func main() {
	var opts options
	parser := flags.NewParser(&opts, flags.Default)
	parser.Parse()
	if opts.Version {
		fmt.Println(util.SemVersion)
		return
	}

	cfg, err := loadConfig()
	if err != nil {
		cgi.Serve(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			http.Error(rw, fmt.Sprintf("Config error: %v\n", err), http.StatusInternalServerError)
		}))
		log.Fatalf("error: %v\n", err)
	}

	c, err := newController(cfg)
	if err != nil {
		log.Fatalf("error: %v\n", err)
	}
	pim := newPathInfoMux()
	c.bind(pim)

	if err := cgi.Serve(pim); err != nil {
                if err.Error() == "cgi: no REQUEST_METHOD in environment" {
                    fmt.Println(help_message)
                    fmt.Println("In version: " + util.SemVersion)
                }
                log.Fatalf("error: %v\n", err)
	}
}
