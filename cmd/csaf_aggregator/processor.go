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
	"path/filepath"
	"sync"

	"github.com/csaf-poc/csaf_distribution/csaf"
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

	mirror := p.cfg.Aggregator.Category != nil &&
		*p.cfg.Aggregator.Category == csaf.AggregatorAggregator

	for j := range jobs {
		log.Printf("worker #%d: %s (%s)\n", worker, j.provider.Name, j.provider.Domain)

		if mirror {
			j.err = p.mirror(j.provider)
		}
	}
}

// removeOrphans removes the directories that are not in the providers list.
func (p *processor) removeOrphans() error {

	entries, err := func() ([]os.DirEntry, error) {
		dir, err := os.Open(p.cfg.Web)
		if err != nil {
			return nil, err
		}
		defer dir.Close()
		return dir.ReadDir(-1)
	}()

	if err != nil {
		return err
	}

	keep := make(map[string]bool)
	for _, p := range p.cfg.Providers {
		keep[p.Name] = true
	}

	prefix, err := filepath.Abs(p.cfg.Folder)
	if err != nil {
		return err
	}
	prefix, err = filepath.EvalSymlinks(prefix)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if keep[entry.Name()] {
			continue
		}

		fi, err := entry.Info()
		if err != nil {
			log.Printf("error: %v\n", err)
			continue
		}

		// only remove the symlinks
		if fi.Mode()&os.ModeSymlink != os.ModeSymlink {
			continue
		}

		d := filepath.Join(p.cfg.Web, entry.Name())
		r, err := filepath.EvalSymlinks(d)
		if err != nil {
			log.Printf("error: %v\n", err)
			continue
		}

		fd, err := os.Stat(r)
		if err != nil {
			log.Printf("error: %v\n", err)
			continue
		}

		// If its not a directory its not a mirror.
		if !fd.IsDir() {
			continue
		}

		// Remove the link.
		log.Printf("removing link %s -> %s\n", d, r)
		if err := os.Remove(d); err != nil {
			log.Printf("error: %v\n", err)
			continue
		}

		// Only remove directories which are in our folder.
		if rel, err := filepath.Rel(prefix, r); err == nil && rel == filepath.Base(r) {
			log.Printf("removing directory %s\n", r)
			if err := os.RemoveAll(r); err != nil {
				log.Printf("error: %v\n", err)
			}
		}
	}

	return nil
}

func (p *processor) process() error {
	if err := ensureDir(p.cfg.Folder); err != nil {
		return err
	}
	if err := ensureDir(p.cfg.Web); err != nil {
		return err
	}

	if err := p.removeOrphans(); err != nil {
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
