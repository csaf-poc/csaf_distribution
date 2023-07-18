// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"log"
	"net/http"
	"os"

	"github.com/mitchellh/go-homedir"
)

const defaultWorker = 2

type config struct {
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

	Config *string `short:"c" long:"config" description:"Path to config ini file" value-name:"INI-FILE" no-ini:"true"`
}

// iniPaths are the potential file locations of the the config file.
var iniPaths = []string{
	"~/.config/csaf/downloader.ini",
	"~/.csaf_downloader.ini",
	"csaf_downloader.ini",
}

// findIniFile looks for a file in the pre-defined paths in "iniPaths".
// The returned value will be the name of file if found, otherwise an empty string.
func findIniFile() string {
	for _, f := range iniPaths {
		name, err := homedir.Expand(f)
		if err != nil {
			log.Printf("warn: %v\n", err)
			continue
		}
		if _, err := os.Stat(name); err == nil {
			return name
		}
	}
	return ""
}

// prepare prepares internal state of a loaded configuration.
func (cfg *config) prepare() error {
	// TODO: Implement me!
	return nil
}
