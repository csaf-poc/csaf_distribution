// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"log"
	"os"
	"sync"
	"time"
)

type processor struct {
	cfg *config
}

type job struct {
	provider *provider
	err      error
}

func ensureDir(path string) error {
	_, err := os.Stat(path)
	if err != nil && os.IsNotExist(err) {
		return os.MkdirAll(path, 0750)
	}
	return err
}

func (p *processor) handleProvider(wg *sync.WaitGroup, worker int, jobs <-chan job) {
	defer wg.Done()
	for j := range jobs {
		log.Printf("worker #%d: %s (%s)\n", worker, j.provider.Name, j.provider.Domain)
		time.Sleep(time.Second / 2)
	}
}

func (p *processor) process() error {
	if err := ensureDir(p.cfg.Folder); err != nil {
		return err
	}
	if err := ensureDir(p.cfg.Web); err != nil {
		return err
	}

	var wg sync.WaitGroup

	jobs := make(chan job)

	log.Printf("Starting %d workers.\n", p.cfg.Workers)
	for i := 1; i <= p.cfg.Workers; i++ {
		wg.Add(1)
		go p.handleProvider(&wg, i, jobs)
	}

	for _, p := range p.cfg.Providers {
		jobs <- job{provider: p}
	}
	close(jobs)

	wg.Wait()

	return nil
}
