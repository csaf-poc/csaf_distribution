// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/csaf-poc/csaf_distribution/csaf"
	"github.com/csaf-poc/csaf_distribution/util"
)

type fullJob struct {
	provider           *provider
	aggregatorProvider *csaf.AggregatorCSAFProvider
	err                error
}

// setupProviderFull fetches the provider-metadate.json for a specific provider.
func (w *worker) setupProviderFull(provider *provider) error {
	log.Printf("worker #%d: %s (%s)\n",
		w.num, provider.Name, provider.Domain)

	w.dir = ""
	w.provider = provider

	// Each job needs a separate client.
	w.client = w.cfg.httpClient(provider)

	// We need the provider metadata in all cases.
	if err := w.locateProviderMetadata(provider.Domain); err != nil {
		return err
	}

	// Validate the provider metadata.
	errors, err := csaf.ValidateProviderMetadata(w.metadataProvider)
	if err != nil {
		return err
	}
	if len(errors) > 0 {
		return fmt.Errorf(
			"provider-metadata.json has %d validation issues", len(errors))
	}

	log.Printf("provider-metadata: %s\n", w.loc)
	return nil
}

// fullWorkFunc implements the actual work (mirror/list).
type fullWorkFunc func(*worker) (*csaf.AggregatorCSAFProvider, error)

// fullWork handles the treatment of providers concurrently.
func (w *worker) fullWork(
	wg *sync.WaitGroup,
	doWork fullWorkFunc,
	jobs <-chan *fullJob,
) {
	defer wg.Done()

	for j := range jobs {
		if err := w.setupProviderFull(j.provider); err != nil {
			j.err = err
			continue
		}
		j.aggregatorProvider, j.err = doWork(w)
	}
}

// full performs the complete lister/download
func (p *processor) full() error {

	var doWork fullWorkFunc

	if p.cfg.runAsMirror() {
		doWork = (*worker).mirror
		log.Println("Running in aggregator mode")
	} else {
		doWork = (*worker).lister
		log.Println("Running in lister mode")
	}

	queue := make(chan *fullJob)
	var wg sync.WaitGroup

	log.Printf("Starting %d workers.\n", p.cfg.Workers)
	for i := 1; i <= p.cfg.Workers; i++ {
		wg.Add(1)
		w := newWorker(i, p.cfg)
		go w.fullWork(&wg, doWork, queue)
	}

	jobs := make([]fullJob, len(p.cfg.Providers))

	for i, p := range p.cfg.Providers {
		jobs[i] = fullJob{provider: p}
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
		if j.aggregatorProvider == nil {
			log.Printf(
				"error: '%s' does not produce any result.\n", j.provider.Name)
			continue
		}
		csafProviders = append(csafProviders, j.aggregatorProvider)
	}

	if len(csafProviders) == 0 {
		return errors.New("all jobs failed, stopping")
	}

	version := csaf.AggregatorVersion20
	canonicalURL := csaf.AggregatorURL(
		p.cfg.Domain + "/.well-known/csaf-aggregator/aggregator.json")

	lastUpdated := csaf.TimeStamp(time.Now().UTC())

	agg := csaf.Aggregator{
		Aggregator:    &p.cfg.Aggregator,
		Version:       &version,
		CanonicalURL:  &canonicalURL,
		CSAFProviders: csafProviders,
		LastUpdated:   &lastUpdated,
	}

	web := filepath.Join(p.cfg.Web, ".well-known", "csaf-aggregator")

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
