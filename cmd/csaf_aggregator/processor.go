// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/csaf-poc/csaf_distribution/csaf"
	"github.com/csaf-poc/csaf_distribution/util"
)

type processor struct {
	cfg *config
}

type job struct {
	provider *provider
	result   *csaf.AggregatorCSAFProvider
	err      error
}

type summary struct {
	filename string
	summary  *csaf.AdvisorySummary
}

type worker struct {
	num      int
	expr     *util.PathEval
	cfg      *config
	signRing *crypto.KeyRing

	client           client               // client per provider
	provider         *provider            // current provider
	metadataProvider interface{}          // current metadata provider
	loc              string               // URL of current provider-metadata.json
	dir              string               // Directory to store data to.
	summaries        map[string][]summary // the summaries of the advisories.
}

func newWorker(num int, config *config) *worker {
	return &worker{
		num:  num,
		cfg:  config,
		expr: util.NewPathEval(),
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
		filepath.Join(w.cfg.Folder, w.provider.Name))
	if err == nil {
		w.dir = dir
	}
	return dir, err
}

func (w *worker) doMirror(j *job) {
	if j.result, j.err = w.mirror(); j.err != nil && w.dir != "" {
		// If something goes wrong remove the debris.
		if err := os.RemoveAll(w.dir); err != nil {
			log.Printf("error: %v\n", err)
		}
	}
}

func (w *worker) doLister(j *job) {
	j.err = errors.New("not implemented,yet!")
}

func (w *worker) work(
	wg *sync.WaitGroup,
	doWork func(*worker) (*csaf.AggregatorCSAFProvider, error),
	jobs <-chan *job,
) {
	defer wg.Done()

	for j := range jobs {
		log.Printf("worker #%d: %s (%s)\n",
			w.num, j.provider.Name, j.provider.Domain)

		w.dir = ""
		w.provider = j.provider

		// Each job needs a separate client.
		w.client = w.cfg.httpClient(j.provider)

		// We need the provider metadata in all cases.
		if err := w.locateProviderMetadata(j.provider.Domain); err != nil {
			j.err = err
			continue
		}

		// Validate the provider metadata.
		errors, err := csaf.ValidateProviderMetadata(w.metadataProvider)
		if err != nil {
			j.err = err
			continue
		}
		if len(errors) > 0 {
			j.err = fmt.Errorf(
				"provider-metadata.json has %d validation issues", len(errors))
			continue
		}

		log.Printf("provider-metadata: %s\n", w.loc)

		j.result, j.err = doWork(w)
	}
}

var providerMetadataLocations = [...]string{
	".well-known/csaf",
	"security/data/csaf",
	"advisories/csaf",
	"security/csaf",
}

func (w *worker) locateProviderMetadata(domain string) error {

	w.metadataProvider = nil

	download := func(r io.Reader) error {
		if err := json.NewDecoder(r).Decode(&w.metadataProvider); err != nil {
			log.Printf("error: %s\n", err)
			return errNotFound
		}
		return nil
	}

	for _, loc := range providerMetadataLocations {
		url := "https://" + domain + "/" + loc
		if err := downloadJSON(w.client, url, download); err != nil {
			if err == errNotFound {
				continue
			}
			return err
		}
		if w.metadataProvider != nil {
			w.loc = loc
			return nil
		}
	}

	// Read from security.txt

	path := "https://" + domain + "/.well-known/security.txt"
	res, err := w.client.Get(path)
	if err != nil {
		return err
	}

	if res.StatusCode != http.StatusOK {
		return errNotFound
	}

	if err := func() error {
		defer res.Body.Close()
		urls, err := csaf.ExtractProviderURL(res.Body, false)
		if err != nil {
			return err
		}
		if len(urls) == 0 {
			return errors.New("No provider-metadata.json found in secturity.txt")
		}
		w.loc = urls[0]
		return nil
	}(); err != nil {
		return err
	}

	return downloadJSON(w.client, w.loc, download)
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

	var wg sync.WaitGroup

	queue := make(chan *job)

	var doWork func(*worker) (*csaf.AggregatorCSAFProvider, error)

	mirror := p.cfg.runAsMirror()

	if mirror {
		doWork = (*worker).mirror
		log.Println("Running in aggregator mode")
	} else {
		doWork = (*worker).lister
		log.Println("Running in lister mode")
	}

	log.Printf("Starting %d workers.\n", p.cfg.Workers)
	for i := 1; i <= p.cfg.Workers; i++ {
		wg.Add(1)
		w := newWorker(i, p.cfg)
		go w.work(&wg, doWork, queue)
	}

	jobs := make([]job, len(p.cfg.Providers))

	for i, p := range p.cfg.Providers {
		jobs[i] = job{provider: p}
		queue <- &jobs[i]
	}
	close(queue)

	wg.Wait()

	// Assemble aggregator data structure.

	csafProviders := make([]*csaf.AggregatorCSAFProvider, 0, len(jobs))

	for i := range jobs {
		j := &jobs[i]
		if j.err != nil {
			log.Printf("error: '%s' failed: %v\n", j.provider.Name, j.err)
			continue
		}
		if j.result == nil {
			log.Printf(
				"error: '%s' does not produce any result.\n", j.provider.Name)
			continue
		}
		csafProviders = append(csafProviders, j.result)
	}

	if len(csafProviders) == 0 {
		return errors.New("all jobs failed, stopping")
	}

	version := csaf.AggregatorVersion20
	canonicalURL := csaf.AggregatorURL(
		p.cfg.Domain + "/.well-known/csaf-aggregator/aggregator.json")

	lastUpdated := csaf.TimeStamp(time.Now())

	agg := csaf.Aggregator{
		Aggregator:    &p.cfg.Aggregator,
		Version:       &version,
		CanonicalURL:  &canonicalURL,
		CSAFProviders: csafProviders,
		LastUpdated:   &lastUpdated,
	}

	dstName := filepath.Join(web, "aggregator.json")

	fname, file, err := util.MakeUniqFile(dstName + ".tmp")
	if err != nil {
		return err
	}

	if _, err := agg.WriteTo(file); err != nil {
		file.Close()
		os.RemoveAll(fname)
		return err
	}

	if err := file.Close(); err != nil {
		return err
	}

	return os.Rename(fname, dstName)
}
