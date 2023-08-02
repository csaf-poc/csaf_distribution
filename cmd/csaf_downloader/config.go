// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"crypto/tls"
	"net/http"

	"github.com/csaf-poc/csaf_distribution/v2/internal/certs"
	"github.com/csaf-poc/csaf_distribution/v2/internal/filter"
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
	ClientCert           *string           `long:"client-cert" description:"TLS client certificate file (PEM encoded data)" value-name:"CERT-FILE" toml:"client_cert"`
	ClientKey            *string           `long:"client-key" description:"TLS client private key file (PEM encoded data)" value-name:"KEY-FILE" toml:"client_key"`
	ClientPassphrase     *string           `long:"client-passphrase" description:"Optional passphrase for the client certificate" value-name:"PASSPHRASE" toml:"client_passphrase"`
	Version              bool              `long:"version" description:"Display version of the binary" toml:"-"`
	Verbose              bool              `long:"verbose" short:"v" description:"Verbose output" toml:"verbose"`
	Rate                 *float64          `long:"rate" short:"r" description:"The average upper limit of https operations per second (defaults to unlimited)" toml:"rate"`
	Worker               int               `long:"worker" short:"w" description:"NUMber of concurrent downloads" value-name:"NUM" toml:"worker"`
	Range                *models.TimeRange `long:"timerange" short:"t" description:"RANGE of time from which advisories to download" value-name:"RANGE" toml:"timerange"`
	Folder               string            `long:"folder" short:"f" description:"Download into a given FOLDER" value-name:"FOLDER" toml:"folder"`
	IgnorePattern        []string          `long:"ignorepattern" short:"i" description:"Dont download files if there URLs match any of the given PATTERNs" value-name:"PATTERN" toml:"ignorepattern"`

	ExtraHeader http.Header `long:"header" short:"H" description:"One or more extra HTTP header fields" toml:"header"`

	RemoteValidator        string   `long:"validator" description:"URL to validate documents remotely" value-name:"URL" toml:"validator"`
	RemoteValidatorCache   string   `long:"validatorcache" description:"FILE to cache remote validations" value-name:"FILE" toml:"validatorcache"`
	RemoteValidatorPresets []string `long:"validatorpreset" description:"One or more PRESETS to validate remotely" value-name:"PRESETS" toml:"validatorpreset"`

	Config string `short:"c" long:"config" description:"Path to config TOML file" value-name:"TOML-FILE" toml:"-"`

	clientCerts   []tls.Certificate
	ignorePattern filter.PatternMatcher
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
		ConfigLocation:         func(cfg *config) string { return cfg.Config },
		Usage:                  "[OPTIONS] domain...",
		HasVersion:             func(cfg *config) bool { return cfg.Version },
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

// ignoreFile returns true if the given URL should not be downloaded.
func (cfg *config) ignoreURL(u string) bool {
	return cfg.ignorePattern.Matches(u)
}

// compileIgnorePatterns compiles the configure patterns to be ignored.
func (cfg *config) compileIgnorePatterns() error {
	pm, err := filter.NewPatternMatcher(cfg.IgnorePattern)
	if err != nil {
		return err
	}
	cfg.ignorePattern = pm
	return nil
}

// prepareCertificates loads the client side certificates used by the HTTP client.
func (cfg *config) prepareCertificates() error {
	cert, err := certs.LoadCertificate(
		cfg.ClientCert, cfg.ClientKey, cfg.ClientPassphrase)
	if err != nil {
		return err
	}
	cfg.clientCerts = cert
	return nil
}

// prepare prepares internal state of a loaded configuration.
func (cfg *config) prepare() error {
	if err := cfg.prepareCertificates(); err != nil {
		return err
	}
	return cfg.compileIgnorePatterns()
}
