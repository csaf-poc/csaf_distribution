// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

// Package main implements the csaf_downloader tool.
package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/csaf-poc/csaf_distribution/v3/csaf"
	"github.com/csaf-poc/csaf_distribution/v3/internal/options"
	"github.com/csaf-poc/csaf_distribution/v3/lib/downloader"
	"github.com/csaf-poc/csaf_distribution/v3/util"
)

// failedForwardDir is the name of the special sub folder
// where advisories get stored which fail forwarding.
const failedForwardDir = "failed_forward"

// failedValidationDir is the name of the sub folder
// where advisories are stored that fail validation in
// unsafe mode.
const failedValidationDir = "failed_validation"

var mkdirMu sync.Mutex

func run(cfg *config, domains []string) error {
	dCfg, err := cfg.GetDownloadConfig()
	if err != nil {
		return err
	}

	dCfg.DownloadHandler = downloadHandler(cfg)
	dCfg.FailedForwardHandler = storeFailedAdvisory(cfg)

	d, err := downloader.NewDownloader(dCfg)
	if err != nil {
		return err
	}
	defer d.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	if cfg.ForwardURL != "" {
		f := downloader.NewForwarder(dCfg)
		go f.Run()
		defer func() {
			f.Log()
			f.Close()
		}()
		d.Forwarder = f
	}

	// If the enumerate-only flag is set, enumerate found PMDs,
	// else use the normal load method
	if cfg.EnumeratePMDOnly {
		return d.RunEnumerate(domains)
	}
	return d.Run(ctx, domains)
}

func mkdirAll(path string, perm os.FileMode) error {
	mkdirMu.Lock()
	defer mkdirMu.Unlock()
	return os.MkdirAll(path, perm)
}

func extractInitialReleaseDate(doc any) time.Time {
	var initialReleaseDate time.Time
	dateExtract := util.TimeMatcher(&initialReleaseDate, time.RFC3339)

	eval := util.NewPathEval()

	if err := eval.Extract(
		`$.document.tracking.initial_release_date`, dateExtract, false, doc,
	); err != nil {
		slog.Warn("Cannot extract initial_release_date from advisory")
		initialReleaseDate = time.Now()
	}
	initialReleaseDate = initialReleaseDate.UTC()
	return initialReleaseDate
}

func extractTLP(doc any) csaf.TLPLabel {
	eval := util.NewPathEval()
	labelString, err := eval.Eval(`$.document.distribution.tlp.label`, doc)
	if err != nil {
		return csaf.TLPLabelUnlabeled
	}
	label, ok := labelString.(string)
	if !ok {
		return csaf.TLPLabelUnlabeled
	}
	return csaf.TLPLabel(label)
}

func downloadHandler(cfg *config) func(d downloader.DownloadedDocument) error {
	return func(d downloader.DownloadedDocument) error {
		if cfg.NoStore {
			// Do not write locally.
			if d.ValStatus == downloader.ValidValidationStatus {
				return nil
			}
		}

		var lastDir string

		// Advisories that failed validation are stored in a special folder.
		var newDir string
		if d.ValStatus != downloader.ValidValidationStatus {
			newDir = path.Join(cfg.Directory, failedValidationDir)
		} else {
			newDir = cfg.Directory
		}

		var doc any
		if err := json.Unmarshal(d.Data, &doc); err != nil {
			slog.Error("Could not parse json document", "err", err)
			return nil
		}

		initialReleaseDate := extractInitialReleaseDate(doc)
		label := extractTLP(doc)

		lower := strings.ToLower(string(label))

		// Do we have a configured destination folder?
		if cfg.Folder != "" {
			newDir = path.Join(newDir, cfg.Folder)
		} else {
			newDir = path.Join(newDir, lower, strconv.Itoa(initialReleaseDate.Year()))
		}

		if newDir != lastDir {
			if err := mkdirAll(newDir, 0755); err != nil {
				return err
			}
			lastDir = newDir
		}

		// Write advisory to file
		filePath := filepath.Join(lastDir, d.Filename)

		for _, x := range []struct {
			p string
			d []byte
		}{
			{filePath, d.Data},
			{filePath + ".sha256", d.SHA256},
			{filePath + ".sha512", d.SHA512},
			{filePath + ".asc", d.SignData},
		} {
			if x.d != nil {
				if err := os.WriteFile(x.p, x.d, 0644); err != nil {
					return err
				}
			}
		}

		slog.Info("Written advisory", "path", filePath)
		return nil
	}
}

// storeFailedAdvisory stores an advisory in a special folder
// in case the forwarding failed.
func storeFailedAdvisory(cfg *config) func(filename, doc, sha256, sha512 string) error {
	return func(filename, doc, sha256, sha512 string) error {
		// Create special folder if it does not exist.
		dir := filepath.Join(cfg.Directory, failedForwardDir)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
		// Store parts which are not empty.
		for _, x := range []struct {
			p string
			d string
		}{
			{filename, doc},
			{filename + ".sha256", sha256},
			{filename + ".sha512", sha512},
		} {
			if len(x.d) != 0 {
				p := filepath.Join(dir, x.p)
				if err := os.WriteFile(p, []byte(x.d), 0644); err != nil {
					return err
				}
			}
		}
		return nil
	}
}

func main() {
	domains, cfg, err := parseArgsConfig()
	options.ErrorCheck(err)

	if len(domains) == 0 {
		slog.Warn("No domains given.")
		return
	}

	options.ErrorCheck(run(cfg, domains))
}
