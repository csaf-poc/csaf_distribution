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
	"github.com/csaf-poc/csaf_distribution/v3/lib/downloader"
	"log/slog"
	"os"
	"os/signal"

	"github.com/csaf-poc/csaf_distribution/v3/internal/options"
)

const (
	defaultWorker         = 2
	defaultPreset         = "mandatory"
	defaultForwardQueue   = 5
	defaultValidationMode = downloader.ValidationStrict
	defaultLogFile        = "downloader.log"
	defaultLogLevel       = slog.LevelInfo
)

// configPaths are the potential file locations of the Config file.
var configPaths = []string{
	"~/.config/csaf/downloader.toml",
	"~/.csaf_downloader.toml",
	"csaf_downloader.toml",
}

// parseArgsConfig parses the command line and if needed a config file.
func parseArgsConfig() ([]string, *downloader.Config, error) {
	var (
		logFile  = defaultLogFile
		logLevel = &options.LogLevel{Level: defaultLogLevel}
	)
	p := options.Parser[downloader.Config]{
		DefaultConfigLocations: configPaths,
		ConfigLocation:         func(cfg *downloader.Config) string { return cfg.Config },
		Usage:                  "[OPTIONS] domain...",
		HasVersion:             func(cfg *downloader.Config) bool { return cfg.Version },
		SetDefaults: func(cfg *downloader.Config) {
			cfg.Worker = defaultWorker
			cfg.RemoteValidatorPresets = []string{defaultPreset}
			cfg.ValidationMode = defaultValidationMode
			cfg.ForwardQueue = defaultForwardQueue
			cfg.LogFile = &logFile
			cfg.LogLevel = logLevel
		},
		// Re-establish default values if not set.
		EnsureDefaults: func(cfg *downloader.Config) {
			if cfg.Worker == 0 {
				cfg.Worker = defaultWorker
			}
			if cfg.RemoteValidatorPresets == nil {
				cfg.RemoteValidatorPresets = []string{defaultPreset}
			}
			switch cfg.ValidationMode {
			case downloader.ValidationStrict, downloader.ValidationUnsafe:
			default:
				cfg.ValidationMode = downloader.ValidationStrict
			}
			if cfg.LogFile == nil {
				cfg.LogFile = &logFile
			}
			if cfg.LogLevel == nil {
				cfg.LogLevel = logLevel
			}
		},
	}
	return p.Parse()
}

func run(cfg *downloader.Config, domains []string) error {
	d, err := downloader.NewDownloader(cfg)
	if err != nil {
		return err
	}
	defer d.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	if cfg.ForwardURL != "" {
		f := downloader.NewForwarder(cfg)
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

func main() {

	domains, cfg, err := parseArgsConfig()
	options.ErrorCheck(err)
	options.ErrorCheck(cfg.Prepare())

	if len(domains) == 0 {
		slog.Warn("No domains given.")
		return
	}

	options.ErrorCheck(run(cfg, domains))
}
