// Package options contains helpers to handle command line options and config files.
package options

import (
	"fmt"
	"os"
	"testing"
)

type config struct {
	Test           string `long:"Test" description:"Test config struct"`
	Version        bool   `long:"version" description:"test print version"`
	ConfigLocation string `long:"configlocation" description:"test location"`
}

// Parser helps parsing command line arguments and loading
// stored configurations from file.
func TestParse(t *testing.T) {
	os.Args = []string{"cmd"}
	defaultConfigLocation := []string{"data/config.toml"}
	p := Parser[config]{
		DefaultConfigLocations: defaultConfigLocation,
		ConfigLocation: func(cfg *config) string {
			return cfg.ConfigLocation
		},
		Usage:      "[OPTIONS] domain...",
		HasVersion: func(cfg *config) bool { return cfg.Version },
		SetDefaults: func(cfg *config) {
		},
		// Re-establish default values if not set.
		EnsureDefaults: func(cfg *config) {
		},
	}

	// Test searching for data/config.toml as config file
	if _, _, err := p.Parse(); err != nil {
		t.Errorf("Failure: Valid Parser using config location failed.")
	}

	// Test invalid flag
	os.Args = []string{"cmd", "--invalid"}
	fmt.Println("The following test should produce a warning.")
	if _, _, err := p.Parse(); err == nil {
		t.Errorf("Failure: Parsed invalid flag 'invalid'")
	}

	// Test with no default location; no config is loaded
	var emptyLocation []string
	p.DefaultConfigLocations = emptyLocation
	os.Args = []string{"cmd"}
	if _, _, err := p.Parse(); err != nil {
		t.Errorf("Failure: Valid Parser without config location failed: %s", err.Error())
	}

	// Test failing to load TOML file
	os.Args = []string{"cmd", "--configlocation=data/config_surplus.toml"}
	if _, _, err := p.Parse(); err == nil {
		t.Errorf("Failure: Parsed invalid toml file.")
	}

	// Test failing to expand Path
	os.Args = []string{"cmd", "--configlocation=~~"}
	if _, _, err := p.Parse(); err == nil {
		t.Errorf("Failure: Invalid path expanded.")
	}
	// fmt.Println(p.Parse())
}

func TestFindConfigFile(t *testing.T) {
	locations := []string{"data/config.toml"}
	notLocation := []string{"notomllocation"}
	errorExpandLocation := []string{"~~"}

	if findConfigFile(locations) != "data/config.toml" {
		t.Errorf("Failure: Couldn't find existing toml file in specified location")
	}
	if !(findConfigFile(notLocation) == "") {
		t.Errorf("Failure: Supposedly found configuration file in nonexistant location")
	}
	fmt.Println("The following test should produce a warning.")
	if !(findConfigFile(errorExpandLocation) == "") {
		t.Errorf("Failure: Supposedly found configuration file in nonexistant location")
	}
}

func TestLoadToml(t *testing.T) {
	var cfg config
	if err := loadTOML(&cfg, "data/nonexistant.toml"); err.Error() != "open "+
		"data/nonexistant.toml: no such file or directory" {
		t.Errorf("Failure: Didn't throw the correct " +
			"error on trying to load nonexistant file")
	}
	if err := loadTOML(&cfg, "data/config_plus.toml"); err.Error() != "could not parse [\"surplus\"] "+
		"from \"data/config_plus.toml\"" {
		t.Errorf("Failure: Succeeded in parsing nonexistant parameter")
	}
	if err := loadTOML(&cfg, "data/config.toml"); err != nil {
		t.Errorf(err.Error())
	}
}
