// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/csaf-poc/csaf_distribution/csaf"
)

func main() {

	var (
		url     = flag.String("url", "", "URL to the validation service")
		presets = flag.String("presets", "", "validation presets")
		cache   = flag.String("cache", "", "cache")
	)

	flag.Parse()

	var pres []string

	if *presets != "" {
		pres = strings.Split(*presets, ",")
	}

	options := csaf.RemoteValidatorOptions{
		URL:     *url,
		Presets: pres,
		Cache:   *cache,
	}

	validator, err := options.Open()
	if err != nil {
		log.Fatalf("error: %v\n", err)
	}
	defer validator.Close()

	for _, arg := range flag.Args() {
		doc, err := func() (interface{}, error) {
			f, err := os.Open(arg)
			if err != nil {
				return nil, err
			}
			defer f.Close()
			dec := json.NewDecoder(f)
			var doc interface{}
			err = dec.Decode(&doc)
			return doc, err
		}()

		if err != nil {
			log.Fatalf("error: %v\n", err)
		}

		valid, err := validator.Validate(doc)
		if err != nil {
			log.Fatalf("error: %v\n", err)
		}

		fmt.Printf("%s: %t\n", arg, valid)
	}
}
