// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/csaf-poc/csaf_distribution/util"
)

type interimJob struct {
	provider *provider
	err      error
}

var errNothingToDo = errors.New("nothing to do")

func (w *worker) interimWork(wg *sync.WaitGroup, jobs <-chan *interimJob) {
	defer wg.Done()
	for j := range jobs {
		// TODO: Implement me!
		j.err = errors.New("not implemented, yet")
	}
}

// joinErrors creates an aggregated error of the messages
// of the given errors.
func joinErrors(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	var b strings.Builder
	for i, err := range errs {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(err.Error())
	}
	return errors.New(b.String())
}

// interim performs the short interim check/update.
func (p *processor) interim() error {

	if !p.cfg.runAsMirror() {
		return errors.New("iterim in lister mode does not work")
	}

	queue := make(chan *interimJob)
	var wg sync.WaitGroup

	log.Printf("Starting %d workers.\n", p.cfg.Workers)
	for i := 1; i <= p.cfg.Workers; i++ {
		wg.Add(1)
		w := newWorker(i, p.cfg)
		go w.interimWork(&wg, queue)
	}

	jobs := make([]interimJob, len(p.cfg.Providers))

	for i, p := range p.cfg.Providers {
		jobs[i] = interimJob{provider: p}
		queue <- &jobs[i]
	}
	close(queue)

	wg.Wait()

	var errs []error

	for i := range jobs {
		if err := jobs[i].err; err != nil {
			if err != errNothingToDo {
				errs = append(errs, err)
				continue
			}
			log.Printf("Nothing to do for provider %s\n",
				jobs[i].provider.Name)
		}
	}

	return joinErrors(errs)
}

// loadChangesFromReader scans a changes.csv file for matching
// iterim advisories. changes.txt are sorted with youngest
// first, so we can stop scanning if entries get too old.
func loadChangesFromReader(
	r io.Reader,
	accept func(time.Time, string) (bool, bool),
) ([]string, error) {

	changes := csv.NewReader(r)
	changes.FieldsPerRecord = 2

	var files []string

	for {
		record, err := changes.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		t, err := time.Parse(time.RFC3339, record[0])
		if err != nil {
			return nil, err
		}
		take, cont := accept(t, record[1])
		if take {
			files = append(files, record[1])
		}
		if !cont {
			break
		}
	}

	return files, nil
}

func scanForInterimFiles(base string, years int) ([]string, error) {

	if years == 0 {
		years = 10_000
	}

	from := time.Now().AddDate(-years, 0, 0)

	pe := util.NewPathEval()

	accept := func(t time.Time, fname string) (bool, bool) {
		if t.Before(from) {
			return false, false
		}

		fn := filepath.Join(base, fname)
		f, err := os.Open(fn)
		if err != nil {
			log.Printf("error: %v\n", err)
			return false, true
		}
		defer f.Close()

		var doc interface{}
		if err := json.NewDecoder(f).Decode(&doc); err != nil {
			log.Printf("error: %v\n", err)
			return false, true
		}

		const interimExpr = `$.document.status"`

		var status string
		matches := pe.Extract(interimExpr, util.StringMatcher(&status), doc) == nil &&
			status == "interim"
		return matches, true
	}

	changesF, err := os.Open(filepath.Join(base, "changes.csv"))
	if err != nil {
		return nil, err
	}
	defer changesF.Close()

	return loadChangesFromReader(changesF, accept)
}
