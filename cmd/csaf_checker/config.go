// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/csaf-poc/csaf_distribution/v2/internal/models"
	"github.com/csaf-poc/csaf_distribution/v2/internal/options"
)

type outputFormat string

const (
	defaultPreset = "mandatory"
	defaultFormat = "json"
)

type config struct {
	Output string `short:"o" long:"output" description:"File name of the generated report" value-name:"REPORT-FILE" toml:"output"`
	//lint:ignore SA5008 We are using choice twice: json, html.
	Format      outputFormat      `short:"f" long:"format" choice:"json" choice:"html" description:"Format of report" toml:"format"`
	Insecure    bool              `long:"insecure" description:"Do not check TLS certificates from provider" toml:"insecure"`
	ClientCert  *string           `long:"client-cert" description:"TLS client certificate file (PEM encoded data)" value-name:"CERT-FILE" toml:"client_cert"`
	ClientKey   *string           `long:"client-key" description:"TLS client private key file (PEM encoded data)" value-name:"KEY-FILE" toml:"client_key"`
	Version     bool              `long:"version" description:"Display version of the binary" toml:"-"`
	Verbose     bool              `long:"verbose" short:"v" description:"Verbose output" toml:"verbose"`
	Rate        *float64          `long:"rate" short:"r" description:"The average upper limit of https operations per second (defaults to unlimited)" toml:"rate"`
	Years       *uint             `long:"years" short:"y" description:"Number of years to look back from now" value-name:"YEARS" toml:"years"`
	Range       *models.TimeRange `long:"timerange" short:"t" description:"RANGE of time from which advisories to download" value-name:"RANGE" toml:"timerange"`
	ExtraHeader http.Header       `long:"header" short:"H" description:"One or more extra HTTP header fields" toml:"header"`

	RemoteValidator        string   `long:"validator" description:"URL to validate documents remotely" value-name:"URL" toml:"validator"`
	RemoteValidatorCache   string   `long:"validatorcache" description:"FILE to cache remote validations" value-name:"FILE" toml:"validator_cache"`
	RemoteValidatorPresets []string `long:"validatorpreset" description:"One or more presets to validate remotely" toml:"validator_preset"`

	Config string `short:"c" long:"config" description:"Path to config TOML file" value-name:"TOML-FILE" toml:"-"`

	clientCerts []tls.Certificate
	ageAccept   func(time.Time) bool
}

// configPaths are the potential file locations of the config file.
var configPaths = []string{
	"~/.config/csaf/checker.toml",
	"~/.csaf_checker.toml",
	"csaf_checker.toml",
}

// UnmarshalText implements [encoding/text.TextUnmarshaler].
func (of *outputFormat) UnmarshalText(text []byte) error {
	s := string(text)
	switch s {
	case "html", "json":
		*of = outputFormat(s)
	default:
		return fmt.Errorf(`%q is neither "html" nor "json"`, s)
	}
	return nil
}

// parseArgsConfig parse the command arguments and loads configuration
// from a configuration file.
func parseArgsConfig() ([]string, *config, error) {
	p := options.Parser[config]{
		DefaultConfigLocations: configPaths,
		ConfigLocation: func(cfg *config) string {
			return cfg.Config
		},
		Usage: "[OPTIONS] domain...",
		SetDefaults: func(cfg *config) {
			cfg.Format = defaultFormat
			cfg.RemoteValidatorPresets = []string{defaultPreset}
		},
		// Re-establish default values if not set.
		EnsureDefaults: func(cfg *config) {
			if cfg.Format == "" {
				cfg.Format = defaultFormat
			}
			if cfg.RemoteValidatorPresets == nil {
				cfg.RemoteValidatorPresets = []string{defaultPreset}
			}
		},
	}
	return p.Parse()
}

// protectedAccess returns true if we have client certificates or
// extra http headers configured.
// This may be a wrong assumption, because the certs are not checked
// for their domain and custom headers may have other purposes.
func (cfg *config) protectedAccess() bool {
	return len(cfg.clientCerts) > 0 || len(cfg.ExtraHeader) > 0
}

// prepare prepares internal state of a loaded configuration.
func (cfg *config) prepare() error {
	// Load client certs.
	if err := cfg.prepareCertificates(); err != nil {
		return err
	}

	return cfg.prepareTimeRangeFilter()
}

// prepareCertificates loads the client side certificates used by the HTTP client.
func (cfg *config) prepareCertificates() error {

	switch hasCert, hasKey := cfg.ClientCert != nil, cfg.ClientKey != nil; {

	case hasCert && !hasKey || !hasCert && hasKey:
		return errors.New("both client-key and client-cert options must be set for the authentication")

	case hasCert:
		cert, err := tls.LoadX509KeyPair(*cfg.ClientCert, *cfg.ClientKey)
		if err != nil {
			return err
		}
		cfg.clientCerts = []tls.Certificate{cert}
	}
	return nil
}

// acceptYears returns a filter that accepts advisories from the last years.
func acceptYears(years uint) func(time.Time) bool {
	good := time.Now().AddDate(-int(years), 0, 0)
	return func(t time.Time) bool {
		return !t.Before(good)
	}
}

// prepareTimeRangeFilter sets up the filter in which time range
// advisory should be considered for checking.
func (cfg *config) prepareTimeRangeFilter() error {
	switch {
	case cfg.Years != nil && cfg.Range != nil:
		return errors.New(`"timerange" and "years" are both configured: only one allowed`)

	case cfg.Years != nil:
		cfg.ageAccept = acceptYears(*cfg.Years)

	case cfg.Range != nil:
		cfg.ageAccept = cfg.Range.Contains
	}
	return nil
}
