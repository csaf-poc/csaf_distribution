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
	Output                 string   `short:"o" long:"output" description:"If a remote validator was used, display AMOUNT ('all', 'important' or 'short') results" value-name:"AMOUNT"`
}

// ShortTest is the result of the remote tests
// recieved by the remote validation service
// collapsed into minimal form.
type ShortTest struct {
	Valid   bool                    `json:"isValid"`
	Error   []csaf.RemoteTestResult `json:"errors"`
	Warning []csaf.RemoteTestResult `json:"warnings"`
	Info    []csaf.RemoteTestResult `json:"infos"`
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

	// Select amount level of output for remote validation.
	var printResult func(*csaf.RemoteValidationResult) error
	switch opts.Output {
	case "all":
		printResult = printRemoteValidationResult
	case "short":
		printResult = printShort
	case "important":
		printResult = printImportant
	case "":
		printResult = noPrint
	default:
		return fmt.Errorf("unknown output amount %q", opts.Output)
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
			rvr, err := validator.Validate(doc)
			if err != nil {
				return fmt.Errorf("remote validation of %q failed: %w",
					file, err)
			}
			if err := printResult(rvr); err != nil {
				return fmt.Errorf("remote validation of %q failed: %w",
					file, err)
			}
			var passes string
			if rvr.Valid {
				passes = "passes"
			} else {
				passes = "does not pass"
			}
			fmt.Printf("%q %s remote validation.\n", file, passes)
		}
	}

	return nil
}

func noPrint(*csaf.RemoteValidationResult) error { return nil }

func printShort(rvr *csaf.RemoteValidationResult) error {
	short := ShortTest{
		Valid:   rvr.Valid,
		Info:    []csaf.RemoteTestResult{},
		Warning: []csaf.RemoteTestResult{},
		Error:   []csaf.RemoteTestResult{},
	}
	for _, test := range rvr.Tests {
		short.Info = append(short.Info, test.Info...)
		short.Error = append(short.Error, test.Error...)
		short.Warning = append(short.Warning, test.Warning...)
	}
	output, err := json.MarshalIndent(short, "", "    ")
	if err != nil {
		return fmt.Errorf("error while displaying remote validator result")
	}
	_, err = fmt.Println(string(output))
	return err
}

func printImportant(rvr *csaf.RemoteValidationResult) error {
	important := csaf.RemoteValidationResult{
		Valid: rvr.Valid,
		Tests: []csaf.RemoteTest{},
	}
	for _, test := range rvr.Tests {
		if len(test.Info) > 0 || len(test.Error) > 0 || len(test.Warning) > 0 {
			important.Tests = append(important.Tests, test)
		}
	}
	return printRemoteValidationResult(&important)
}

func printRemoteValidationResult(in *csaf.RemoteValidationResult) error {
	output, err := json.MarshalIndent(in, "", "    ")
	if err != nil {
		return fmt.Errorf("error while displaying remote validator result")
	}
	fmt.Println(string(output))
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
