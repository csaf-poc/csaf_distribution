// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

// Package main implements the csaf_aggregator tool.
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/csaf-poc/csaf_distribution/util"
	"github.com/gofrs/flock"
	"github.com/jessevdk/go-flags"
)

type options struct {
	Config  string `short:"c" long:"config" description:"File name of the configuration file" value-name:"CFG-FILE" default:"aggregator.toml"`
	Version bool   `long:"version" description:"Display version of the binary"`
	Interim bool   `short:"i" long:"interim" description:"Perform an interim scan"`
}

func errCheck(err error) {
	if err != nil {
		if flags.WroteHelp(err) {
			os.Exit(0)
		}
		log.Fatalf("error: %v\n", err)
	}
}

func lock(lockFile *string, fn func() error) error {
	if lockFile == nil {
		// No locking configured.
		return fn()
	}

	err := os.MkdirAll(filepath.Dir(*lockFile), 0700)
	if err != nil {
		return fmt.Errorf("file locking failed: %v", err)
	}

	fl := flock.New(*lockFile)
	locked, err := fl.TryLock()
	if err != nil {
		return fmt.Errorf("file locking failed: %v", err)
	}

	if !locked {
		return fmt.Errorf("cannot acquire file lock at %s. Maybe the CSAF aggregator is already running?", *lockFile)
	}
	defer fl.Unlock()
	return fn()
}

func main() {
	opts := new(options)

	_, err := flags.Parse(opts)
	errCheck(err)

	if opts.Version {
		fmt.Println(util.SemVersion)
		return
	}

	interim := opts.Interim

	cfg, err := loadConfig(opts.Config)
	errCheck(err)

	if interim {
		cfg.Interim = true
	}

	p := processor{cfg: cfg}
	errCheck(lock(cfg.LockFile, p.process))
}
