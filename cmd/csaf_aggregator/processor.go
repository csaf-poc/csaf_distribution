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

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/csaf-poc/csaf_distribution/csaf"
	"github.com/csaf-poc/csaf_distribution/util"
)

type processor struct {
	// cfg is the global configuration.
	cfg *config

	// remoteValidator is a globally configured remote validator.
	remoteValidator csaf.RemoteValidator
}

type summary struct {
	filename string
	summary  *csaf.AdvisorySummary
	url      string
}

type worker struct {
	num       int
	processor *processor

	expr     *util.PathEval
	signRing *crypto.KeyRing

	client           util.Client                // client per provider
	provider         *provider                  // current provider
	metadataProvider any                        // current metadata provider
	loc              string                     // URL of current provider-metadata.json
	dir              string                     // Directory to store data to.
	summaries        map[string][]summary       // the summaries of the advisories.
	categories       map[string]map[string]bool // the categories per label.
}

func newWorker(num int, processor *processor) *worker {
	return &worker{
		num:       num,
		processor: processor,
		expr:      util.NewPathEval(),
	}
}

func ensureDir(path string) error {
	_, err := os.Stat(path)
	if err != nil && os.IsNotExist(err) {
		return os.MkdirAll(path, 0750)
	}
	return err
}

func (w *worker) createDir() (string, error) {
	if w.dir != "" {
		return w.dir, nil
	}
	dir, err := util.MakeUniqDir(
		filepath.Join(w.processor.cfg.Folder, w.provider.Name))
	if err == nil {
		w.dir = dir
	}
	return dir, err
}

func (w *worker) locateProviderMetadata(domain string) error {

	lpmd := csaf.LoadProviderMetadataForDomain(
		w.client, domain, func(format string, args ...any) {
			log.Printf(
				"Looking for provider-metadata.json of '"+domain+"': "+format+"\n", args...)
		})

	if !lpmd.Valid() {
		return fmt.Errorf("no valid provider-metadata.json found for '%s'", domain)
	}

	w.metadataProvider = lpmd.Document
	w.loc = lpmd.URL

	return nil
}

// removeOrphans removes the directories that are not in the providers list.
func (p *processor) removeOrphans() error {

	keep := make(map[string]bool)
	for _, p := range p.cfg.Providers {
		keep[p.Name] = true
	}

	path := filepath.Join(p.cfg.Web, ".well-known", "csaf-aggregator")

	entries, err := func() ([]os.DirEntry, error) {
		dir, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer dir.Close()
		return dir.ReadDir(-1)
	}()

	if err != nil {
		return err
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

		d := filepath.Join(path, entry.Name())
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
		if rel, err := filepath.Rel(prefix, r); err == nil &&
			rel == filepath.Base(r) {
			log.Printf("removing directory %s\n", r)
			if err := os.RemoveAll(r); err != nil {
				log.Printf("error: %v\n", err)
			}
		}
	}

	return nil
}

// process is the main driver of the jobs handled by work.
func (p *processor) process() error {
	if err := ensureDir(p.cfg.Folder); err != nil {
		return err
	}
	web := filepath.Join(p.cfg.Web, ".well-known", "csaf-aggregator")
	if err := ensureDir(web); err != nil {
		return err
	}

	if err := p.removeOrphans(); err != nil {
		return err
	}

	if p.cfg.Interim {
		return p.interim()
	}

	return p.full()
}
