// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

// Package main implements the csaf_downloader tool.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"

	"github.com/csaf-poc/csaf_distribution/v2/internal/options"
)

func run(cfg *config, domains []string) error {
	d, err := newDownloader(cfg)
	if err != nil {
		return err
	}
	defer d.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	return d.run(ctx, domains)
}

func main() {

	domains, cfg, err := parseArgsConfig()
	options.ErrorCheck(err)
	options.ErrorCheck(cfg.prepare())

	if len(domains) == 0 {
		log.Println("No domains given.")
		return
	}

	options.ErrorCheck(run(cfg, domains))
}
