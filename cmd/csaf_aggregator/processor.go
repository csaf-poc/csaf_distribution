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
	"os"
	"path/filepath"
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

// removeOrphans removes the directories that are not in the providers list.
func (p *processor) removeOrphans() error {

	dir, err := os.Open(p.cfg.Web)
	if err != nil {
		return err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
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
		fi, err := entry.Info()
		if err != nil {
			log.Printf("error: %v\n", err)
			continue
		}

		name := entry.Name()
		if keep[name] {
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
		fmt.Printf("%s -> %s\n", entry.Name(), r)

		fd, err := os.Stat(r)
		if err != nil {
			log.Printf("error: %v\n", err)
			continue
		}

		// If its not a drirectory its not a mirror.
		if !fd.IsDir() {
			continue
		}

		// As filepath.HasPrefix it deprecated relate with base name.
		rel, err := filepath.Rel(prefix, r)
		if err != nil {
			log.Printf("error: %v\n", err)
			continue
		}
		if rel != filepath.Base(r) {
			continue
		}
		log.Printf("to remove (link): %s\n", d)
		log.Printf("to remove (orig): %s\n", r)
		if err := os.Remove(d); err != nil {
			log.Printf("error: %v\n", err)
			continue
		}
		if err := os.RemoveAll(r); err != nil {
			log.Printf("error: %v\n", err)
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
