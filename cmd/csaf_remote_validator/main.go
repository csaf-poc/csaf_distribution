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

func loadJSONFromFile(fname string) (interface{}, error) {
	f, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var doc interface{}
	err = json.NewDecoder(f).Decode(&doc)
	return doc, err
}

func process(options *csaf.RemoteValidatorOptions, fnames []string) error {
	validator, err := options.Open()
	if err != nil {
		return err
	}
	defer validator.Close()

	for _, fname := range fnames {
		doc, err := loadJSONFromFile(fname)
		if err != nil {
			return err
		}
		valid, err := validator.Validate(doc)
		if err != nil {
			return err
		}
		fmt.Printf("%s: %t\n", fname, valid)
	}
	return nil
}

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

	if err := process(&options, flag.Args()); err != nil {
		log.Fatalf("error: %v\n", err)
	}
}
