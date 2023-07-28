// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"net/http"

	"github.com/csaf-poc/csaf_distribution/v2/internal/models"
	"github.com/csaf-poc/csaf_distribution/v2/internal/options"
)

const (
	defaultWorker = 2
	defaultPreset = "mandatory"
)

type config struct {
	Directory            *string           `short:"d" long:"directory" description:"DIRectory to store the downloaded files in" value-name:"DIR" toml:"directory"`
	Insecure             bool              `long:"insecure" description:"Do not check TLS certificates from provider" toml:"insecure"`
	IgnoreSignatureCheck bool              `long:"ignoresigcheck" description:"Ignore signature check results, just warn on mismatch" toml:"ignoresigcheck"`
	Version              bool              `long:"version" description:"Display version of the binary" toml:"-"`
	Verbose              bool              `long:"verbose" short:"v" description:"Verbose output" toml:"verbose"`
	Rate                 *float64          `long:"rate" short:"r" description:"The average upper limit of https operations per second (defaults to unlimited)" toml:"rate"`
	Worker               int               `long:"worker" short:"w" description:"NUMber of concurrent downloads" value-name:"NUM" toml:"worker"`
	Range                *models.TimeRange `long:"timerange" short:"t" description:"RANGE of time from which advisories to download" value-name:"RANGE" toml:"timerange"`

	ExtraHeader http.Header `long:"header" short:"H" description:"One or more extra HTTP header fields" toml:"header"`

	RemoteValidator        string   `long:"validator" description:"URL to validate documents remotely" value-name:"URL" toml:"validator"`
	RemoteValidatorCache   string   `long:"validatorcache" description:"FILE to cache remote validations" value-name:"FILE" toml:"validatorcache"`
	RemoteValidatorPresets []string `long:"validatorpreset" description:"One or more PRESETS to validate remotely" value-name:"PRESETS" toml:"validatorpreset"`

	Config string `short:"c" long:"config" description:"Path to config TOML file" value-name:"TOML-FILE" toml:"-"`
}

// configPaths are the potential file locations of the config file.
var configPaths = []string{
	"~/.config/csaf/downloader.toml",
	"~/.csaf_downloader.toml",
	"csaf_downloader.toml",
}

// parseArgsConfig parses the command line and if need a config file.
func parseArgsConfig() ([]string, *config, error) {
	p := options.Parser[config]{
		DefaultConfigLocations: configPaths,
		ConfigLocation: func(cfg *config) string {
			return cfg.Config
		},
		Usage: "[OPTIONS] domain...",
		SetDefaults: func(cfg *config) {
			cfg.Worker = defaultWorker
			cfg.RemoteValidatorPresets = []string{defaultPreset}
		},
		// Re-establish default values if not set.
		EnsureDefaults: func(cfg *config) {
			if cfg.Worker == 0 {
				cfg.Worker = defaultWorker
			}
			if cfg.RemoteValidatorPresets == nil {
				cfg.RemoteValidatorPresets = []string{defaultPreset}
			}
		},
	}
	return p.Parse()
}

// prepare prepares internal state of a loaded configuration.
func (cfg *config) prepare() error {
	// TODO: Implement me!
	return nil
}
