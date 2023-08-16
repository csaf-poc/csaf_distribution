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
	"os"
	"path/filepath"

	"github.com/csaf-poc/csaf_distribution/v2/internal/options"
	"github.com/gofrs/flock"
)

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
	_, cfg, err := parseArgsConfig()
	options.ErrorCheck(err)
	options.ErrorCheck(cfg.prepare())
	p := processor{cfg: cfg}
	options.ErrorCheck(lock(cfg.LockFile, p.process))
}
