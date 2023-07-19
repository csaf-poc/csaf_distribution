// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/csaf-poc/csaf_distribution/v2/util"
	"github.com/jessevdk/go-flags"
	"github.com/mitchellh/go-homedir"
)

const defaultWorker = 2

type config struct {
	Directory            *string  `short:"d" long:"directory" description:"DIRectory to store the downloaded files in" value-name:"DIR" toml:"directory"`
	Insecure             bool     `long:"insecure" description:"Do not check TLS certificates from provider" toml:"insecure"`
	IgnoreSignatureCheck bool     `long:"ignoresigcheck" description:"Ignore signature check results, just warn on mismatch" toml:"ignore_sig_check"`
	Version              bool     `long:"version" description:"Display version of the binary" toml:"-"`
	Verbose              bool     `long:"verbose" short:"v" description:"Verbose output" toml:"verbose"`
	Rate                 *float64 `long:"rate" short:"r" description:"The average upper limit of https operations per second (defaults to unlimited)" toml:"rate"`
	Worker               int      `long:"worker" short:"w" description:"NUMber of concurrent downloads" value-name:"NUM" toml:"worker"`

	ExtraHeader http.Header `long:"header" short:"H" description:"One or more extra HTTP header fields" toml:"header"`

	RemoteValidator        string   `long:"validator" description:"URL to validate documents remotely" value-name:"URL" toml:"validator"`
	RemoteValidatorCache   string   `long:"validatorcache" description:"FILE to cache remote validations" value-name:"FILE" toml:"validator_cache"`
	RemoteValidatorPresets []string `long:"validatorpreset" description:"One or more presets to validate remotely" default:"mandatory" toml:"validator_preset"`

	Config *string `short:"c" long:"config" description:"Path to config TOML file" value-name:"TOML-FILE" toml:"-"`
}

// configPaths are the potential file locations of the the config file.
var configPaths = []string{
	"~/.config/csaf/downloader.toml",
	"~/.csaf_downloader.toml",
	"csaf_downloader.toml",
}

func parseArgsConfig() ([]string, *config, error) {
	cfg := &config{
		Worker:                 defaultWorker,
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

// findConfigFile looks for a file in the pre-defined paths in "configPath".
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

// prepare prepares internal state of a loaded configuration.
func (cfg *config) prepare() error {
	// TODO: Implement me!
	return nil
}

// errCheck checks if err is not nil and terminates
// the program if so.
func errCheck(err error) {
	if err != nil {
		if flags.WroteHelp(err) {
			os.Exit(0)
		}
		log.Fatalf("error: %v\n", err)
	}
}
