// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

// Package main implements the csaf_validator tool.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/csaf-poc/csaf_distribution/csaf"
	"github.com/csaf-poc/csaf_distribution/util"
	"github.com/jessevdk/go-flags"
)

type options struct {
	Version                bool     `long:"version" description:"Display version of the binary"`
	RemoteValidator        string   `long:"validator" description:"URL to validate documents remotely" value-name:"URL"`
	RemoteValidatorCache   string   `long:"validatorcache" description:"FILE to cache remote validations" value-name:"FILE"`
	RemoteValidatorPresets []string `long:"validatorpreset" description:"One or more presets to validate remotely" default:"mandatory"`
}

func main() {
	opts := new(options)

	parser := flags.NewParser(opts, flags.Default)
	parser.Usage = "[OPTIONS] files..."
	files, err := parser.Parse()
	errCheck(err)

	if opts.Version {
		fmt.Println(util.SemVersion)
		return
	}

	if len(files) == 0 {
		log.Println("No files given.")
		return
	}

	errCheck(run(opts, files))
}

// run validates the given files.
func run(opts *options, files []string) error {

	var validator csaf.RemoteValidator

	if opts.RemoteValidator != "" {
		validatorOptions := csaf.RemoteValidatorOptions{
			URL:     opts.RemoteValidator,
			Presets: opts.RemoteValidatorPresets,
			Cache:   opts.RemoteValidatorCache,
		}
		var err error
		if validator, err = validatorOptions.Open(); err != nil {
			return fmt.Errorf(
				"preparing remote validator failed: %w", err)
		}
		defer validator.Close()
	}

	for _, file := range files {
		// Check if the file name is valid.
		if !util.ConformingFileName(filepath.Base(file)) {
			fmt.Printf("%q is not a valid advisory name.\n", file)
		}
		doc, err := loadJSONFromFile(file)
		if err != nil {
			log.Printf("error: loading %q as JSON failed: %v\n", file, err)
			continue
		}
		// Validate agsinst Schema.
		validationErrs, err := csaf.ValidateCSAF(doc)
		if err != nil {
			log.Printf("error: validating %q against schema failed: %v\n",
				file, err)

		}
		if len(validationErrs) > 0 {
			fmt.Printf("schema validation errors of %q\n", file)
			for _, vErr := range validationErrs {
				fmt.Printf("  * %s\n", vErr)
			}
		} else {
			fmt.Printf("%q passes the schema validation.\n", file)
		}
		// Validate against remote validator.
		if validator != nil {
			validate, err := validator.Validate(doc)
			if err != nil {
				return fmt.Errorf("remote validation of %q failed: %w",
					file, err)
			}
			var passes string
			if validate {
				passes = "passes"
			} else {
				passes = "does not pass"
			}
			fmt.Printf("%q %s remote validation.\n", file, passes)
		}
	}

	return nil
}

func errCheck(err error) {
	if err != nil {
		if flags.WroteHelp(err) {
			os.Exit(0)
		}
		log.Fatalf("error: %v\n", err)
	}
}

// loadJSONFromFile loads a JSON document from a file.
func loadJSONFromFile(fname string) (any, error) {
	f, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var doc any
	if err = json.NewDecoder(f).Decode(&doc); err != nil {
		return nil, err
	}
	return doc, err
}
