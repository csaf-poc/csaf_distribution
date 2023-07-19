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
	"log"
	"net/http"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/csaf-poc/csaf_distribution/v2/util"
	"github.com/jessevdk/go-flags"
	"github.com/mitchellh/go-homedir"
)

type config struct {
	Output      string      `short:"o" long:"output" description:"File name of the generated report" value-name:"REPORT-FILE" toml:"output"`
	Format      string      `short:"f" long:"format" choice:"json" choice:"html" description:"Format of report" default:"json" toml:"format"`
	Insecure    bool        `long:"insecure" description:"Do not check TLS certificates from provider" toml:"insecure"`
	ClientCert  *string     `long:"client-cert" description:"TLS client certificate file (PEM encoded data)" value-name:"CERT-FILE" toml:"client_cert"`
	ClientKey   *string     `long:"client-key" description:"TLS client private key file (PEM encoded data)" value-name:"KEY-FILE" toml:"client_key"`
	Version     bool        `long:"version" description:"Display version of the binary" toml:"-"`
	Verbose     bool        `long:"verbose" short:"v" description:"Verbose output" toml:"verbose"`
	Rate        *float64    `long:"rate" short:"r" description:"The average upper limit of https operations per second (defaults to unlimited)" toml:"rate"`
	Years       *uint       `long:"years" short:"y" description:"Number of years to look back from now" value-name:"YEARS" toml:"years"`
	ExtraHeader http.Header `long:"header" short:"H" description:"One or more extra HTTP header fields" toml:"header"`

	RemoteValidator        string   `long:"validator" description:"URL to validate documents remotely" value-name:"URL" toml:"validator"`
	RemoteValidatorCache   string   `long:"validatorcache" description:"FILE to cache remote validations" value-name:"FILE" toml:"validator_cache"`
	RemoteValidatorPresets []string `long:"validatorpreset" description:"One or more presets to validate remotely" default:"mandatory" toml:"validator_preset"`

	Config *string `short:"c" long:"config" description:"Path to config TOML file" value-name:"TOML-FILE" toml:"-"`

	clientCerts []tls.Certificate
}

// parseArgsConfig parse the command arguments and loads configuration
// from a configuration file.
func parseArgsConfig() ([]string, *config, error) {
	cfg := &config{
		RemoteValidatorPresets: []string{"mandatory"},
	}

	parser := flags.NewParser(cfg, flags.Default)
	parser.Usage = "[OPTIONS] domain..."
	args, err := parser.Parse()
	if err != nil {
		return nil, nil, err
	}

	if cfg.Version {
		fmt.Println(util.SemVersion)
		os.Exit(0)
	}

	if cfg.Config != nil {
		path, err := homedir.Expand(*cfg.Config)
		if err != nil {
			return nil, nil, err
		}
		if err := cfg.load(path); err != nil {
			return nil, nil, err
		}
	} else if path := findConfigFile(); path != "" {
		if err := cfg.load(path); err != nil {
			return nil, nil, err
		}
	}

	return args, cfg, nil
}

// configPaths are the potential file locations of the the config file.
var configPaths = []string{
	"~/.config/csaf/checker.toml",
	"~/.csaf_checker.toml",
	"csaf_checker.toml",
}

// findConfigFile looks for a file in the pre-defined paths in "configPaths".
// The returned value will be the name of file if found, otherwise an empty string.
func findConfigFile() string {
	for _, f := range configPaths {
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

// load loads a configuration from file.
func (cfg *config) load(path string) error {
	md, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return err
	}
	if undecoded := md.Undecoded(); len(undecoded) != 0 {
		return fmt.Errorf("could not parse %q from %q", undecoded, path)
	}
	return nil
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

// errCheck checks if err is not nil and terminates the program if so.
func errCheck(err error) {
	if err != nil {
		if flags.WroteHelp(err) {
			os.Exit(0)
		}
		log.Fatalf("error: %v\n", err)
	}
}
