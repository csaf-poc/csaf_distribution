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
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type interimJob struct {
	provider *provider
	err      error
}

var errNothingToDo = errors.New("nothing to do")

func (w *worker) interimWork(wg *sync.WaitGroup, jobs <-chan *interimJob) {
	defer wg.Done()
	path := filepath.Join(w.cfg.Web, ".well-known", "csaf-aggregator")

	for j := range jobs {

		providerPath := filepath.Join(path, j.provider.Name)

		files, err := scanForInterimFiles(
			providerPath, w.cfg.InterimYears)
		if err != nil {
			j.err = err
			continue
		}

		// If we don't have interim files, we have nothing to do.
		if len(files) == 0 {
			j.err = errNothingToDo
			continue
		}

		if err := w.locateProviderMetadata(j.provider.Domain); err != nil {
			j.err = err
			continue
		}

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

// scanForInterimFiles scans a interims.csv file for matching
// iterim advisories. Its sorted with youngest
// first, so we can stop scanning if entries get too old.
func scanForInterimFiles(base string, years int) ([][2]string, error) {

	var tooOld func(time.Time) bool

	if years <= 0 {
		tooOld = func(time.Time) bool { return false }
	} else {
		from := time.Now().AddDate(-years, 0, 0)
		tooOld = func(t time.Time) bool { return t.Before(from) }
	}

	interimsF, err := os.Open(filepath.Join(base, "interims.csv"))
	if err != nil {
		// None existing file -> no interims.
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer interimsF.Close()

	c := csv.NewReader(interimsF)
	c.FieldsPerRecord = 3

	var files [][2]string

	for {
		record, err := c.Read()
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
		if tooOld(t) {
			break
		}
		files = append(files, [2]string{record[1], record[2]})
	}

	return files, nil
}
