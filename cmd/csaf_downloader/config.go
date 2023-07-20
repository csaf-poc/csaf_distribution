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

const (
	defaultWorker = 2
	defaultPreset = "mandatory"
)

type config struct {
	Directory            *string  `short:"d" long:"directory" description:"DIRectory to store the downloaded files in" value-name:"DIR" toml:"directory"`
	Insecure             bool     `long:"insecure" description:"Do not check TLS certificates from provider" toml:"insecure"`
	IgnoreSignatureCheck bool     `long:"ignoresigcheck" description:"Ignore signature check results, just warn on mismatch" toml:"ignoresigcheck"`
	Version              bool     `long:"version" description:"Display version of the binary" toml:"-"`
	Verbose              bool     `long:"verbose" short:"v" description:"Verbose output" toml:"verbose"`
	Rate                 *float64 `long:"rate" short:"r" description:"The average upper limit of https operations per second (defaults to unlimited)" toml:"rate"`
	Worker               int      `long:"worker" short:"w" description:"NUMber of concurrent downloads" value-name:"NUM" toml:"worker"`

	ExtraHeader http.Header `long:"header" short:"H" description:"One or more extra HTTP header fields" toml:"header"`

	RemoteValidator        string   `long:"validator" description:"URL to validate documents remotely" value-name:"URL" toml:"validator"`
	RemoteValidatorCache   string   `long:"validatorcache" description:"FILE to cache remote validations" value-name:"FILE" toml:"validatorcache"`
	RemoteValidatorPresets []string `long:"validatorpreset" description:"One or more PRESETS to validate remotely" value-name:"PRESETS" toml:"validatorpreset"`

	Config string `short:"c" long:"config" description:"Path to config TOML file" value-name:"TOML-FILE" toml:"-"`
}

// configPaths are the potential file locations of the the config file.
var configPaths = []string{
	"~/.config/csaf/downloader.toml",
	"~/.csaf_downloader.toml",
	"csaf_downloader.toml",
}

// newConfig returns a new configuration.
func newConfig() *config {
	return &config{
		Worker:                 defaultWorker,
		RemoteValidatorPresets: []string{defaultPreset},
	}
}

// parseArgsConfig parses the command line and if need a config file.
func parseArgsConfig() ([]string, *config, error) {

	// Parse the command line first.
	cmdLineCfg := newConfig()
	parser := flags.NewParser(cmdLineCfg, flags.Default)
	parser.Usage = "[OPTIONS] domain..."
	args, err := parser.Parse()
	if err != nil {
		return nil, nil, err
	}

	// Directly quit if the version flag was set.
	if cmdLineCfg.Version {
		fmt.Println(util.SemVersion)
		os.Exit(0)
	}

	var path string
	// Do we have a config file explicitly given by command line?
	if cmdLineCfg.Config != "" {
		path = cmdLineCfg.Config
	} else {
		path = findConfigFile()
	}
	// No config file -> We are good.
	if path == "" {
		return args, cmdLineCfg, nil
	}

	if path, err = homedir.Expand(path); err != nil {
		return nil, nil, err
	}

	// Load the config file
	fileCfg := &config{}
	if err := fileCfg.load(path); err != nil {
		return nil, nil, err
	}

	// Parse command line a second time to overwrite the
	// loaded config at places where explicitly command line
	// options where given.
	args, err = flags.NewParser(fileCfg, flags.Default).Parse()
	if err != nil {
		return nil, nil, err
	}

	// Re-establish default values.
	if fileCfg.Worker == 0 {
		fileCfg.Worker = defaultWorker
	}
	if fileCfg.RemoteValidatorPresets == nil {
		fileCfg.RemoteValidatorPresets = []string{defaultPreset}
	}

	return args, fileCfg, nil
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
