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
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/csaf-poc/csaf_distribution/v2/util"
	"github.com/jessevdk/go-flags"
	"github.com/mitchellh/go-homedir"
)

func errCheck(err error) {
	if err != nil {
		if flags.WroteHelp(err) {
			os.Exit(0)
		}
		log.Fatalf("error: %v\n", err)
	}
}

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

	cfg := &config{
		Worker: defaultWorker,
	}

	parser := flags.NewParser(cfg, flags.Default)
	parser.Usage = "[OPTIONS] domain..."
	domains, err := parser.Parse()
	errCheck(err)

	if cfg.Version {
		fmt.Println(util.SemVersion)
		return
	}

	if cfg.Config != nil {
		iniParser := flags.NewIniParser(parser)
		iniParser.ParseAsDefaults = true
		name, err := homedir.Expand(*cfg.Config)
		errCheck(err)
		errCheck(iniParser.ParseFile(name))
	} else if iniFile := findIniFile(); iniFile != "" {
		iniParser := flags.NewIniParser(parser)
		iniParser.ParseAsDefaults = true
		errCheck(iniParser.ParseFile(iniFile))
	}

	errCheck(cfg.prepare())

	if len(domains) == 0 {
		log.Println("No domains given.")
		return
	}

	errCheck(run(cfg, domains))
}
