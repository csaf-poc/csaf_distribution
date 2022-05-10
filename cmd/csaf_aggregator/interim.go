// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/csaf-poc/csaf_distribution/csaf"
	"github.com/csaf-poc/csaf_distribution/util"
)

type interimJob struct {
	provider *provider
	err      error
}

func (w *worker) checkInterims(
	tx *lazyTransaction,
	label string,
	interims [][2]string,
) ([]string, error) {

	var data bytes.Buffer

	labelPath := filepath.Join(tx.Src(), label)

	// advisories which are not interim any longer.
	var finalized []string

	for _, interim := range interims {

		local := filepath.Join(labelPath, interim[0])
		url := interim[1]

		// Load local SHA256 of the advisory
		localHash, err := util.HashFromFile(local + ".sha256")
		if err != nil {
			return nil, nil
		}

		res, err := w.client.Get(url)
		if err != nil {
			return nil, err
		}
		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetching %s failed: Status code %d (%s)",
				url, res.StatusCode, res.Status)
		}

		s256 := sha256.New()
		data.Reset()
		hasher := io.MultiWriter(s256, &data)

		var doc interface{}
		if err := func() error {
			defer res.Body.Close()
			tee := io.TeeReader(res.Body, hasher)
			return json.NewDecoder(tee).Decode(&doc)
		}(); err != nil {
			return nil, err
		}

		remoteHash := s256.Sum(nil)

		// If the hashes are equal then we can ignore this advisory.
		if bytes.Equal(localHash, remoteHash) {
			continue
		}

		errors, err := csaf.ValidateCSAF(doc)
		if err != nil {
			return nil, fmt.Errorf("failed to validate %s: %v", url, err)
		}

		// XXX: Should we return an error here?
		for _, e := range errors {
			log.Printf("validation error: %s: %v\n", url, e)
		}

		// We need to write the changed content.

		// This will start the transcation if not already started.
		dst, err := tx.Dst()
		if err != nil {
			return nil, err
		}

		// Overwrite in the cloned folder.
		nlocal := filepath.Join(dst, label, interim[0])

		bytes := data.Bytes()

		if err := os.WriteFile(nlocal, bytes, 0644); err != nil {
			return nil, err
		}

		name := filepath.Base(nlocal)

		if err := util.WriteHashToFile(
			nlocal+".sha512", name, sha512.New(), bytes,
		); err != nil {
			return nil, err
		}
		if err := util.WriteHashSumToFile(
			nlocal+".sha256", name, remoteHash,
		); err != nil {
			return nil, err
		}

		// Download the signature
		sigURL := url + ".asc"
		ascFile := nlocal + ".asc"

		// Download the signature or sign it our self.
		if err := w.downloadSignatureOrSign(sigURL, ascFile, bytes); err != nil {
			return nil, err
		}
	}

	return finalized, nil
}

// setupProviderInterim prepares the worker for a specific provider.
func (w *worker) setupProviderInterim(provider *provider) {
	log.Printf("worker #%d: %s (%s)\n",
		w.num, provider.Name, provider.Domain)

	w.dir = ""
	w.provider = provider

	// Each job needs a separate client.
	w.client = w.cfg.httpClient(provider)
}

func (w *worker) interimWork(wg *sync.WaitGroup, jobs <-chan *interimJob) {
	defer wg.Done()
	path := filepath.Join(w.cfg.Web, ".well-known", "csaf-aggregator")

	for j := range jobs {
		w.setupProviderInterim(j.provider)

		providerPath := filepath.Join(path, j.provider.Name)

		j.err = func() error {
			tx := newLazyTransaction(providerPath, w.cfg.Folder)
			defer tx.rollback()

			// Try all the labels
			for _, label := range []string{
				csaf.TLPLabelUnlabeled,
				csaf.TLPLabelWhite,
				csaf.TLPLabelGreen,
				csaf.TLPLabelAmber,
				csaf.TLPLabelRed,
			} {
				label = strings.ToLower(label)
				labelPath := filepath.Join(providerPath, label)

				interimsCSV := filepath.Join(labelPath, "interims.csv")
				interims, err := readInterims(
					interimsCSV, w.cfg.InterimYears)
				if err != nil {
					return err
				}

				// no interims found -> next label.
				if len(interims) == 0 {
					continue
				}

				// Compare locals against remotes.
				finalized, err := w.checkInterims(tx, label, interims)
				if err != nil {
					return err
				}

				if len(finalized) > 0 {
					// We want to write in the transaction folder.
					dst, err := tx.Dst()
					if err != nil {
						return err
					}
					interimsCSV := filepath.Join(dst, label, "interims.csv")
					if err := writeInterims(interimsCSV, finalized); err != nil {
						return err
					}
				}
			}
			return tx.commit()
		}()
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
			errs = append(errs, err)
		}
	}

	return joinErrors(errs)
}

func writeInterims(interimsCSV string, finalized []string) error {

	// In case this is a longer list (unlikely).
	removed := make(map[string]bool, len(finalized))
	for _, f := range finalized {
		removed[f] = true
	}

	lines, err := func() ([][]string, error) {
		interimsF, err := os.Open(interimsCSV)
		if err != nil {
			return nil, err
		}
		defer interimsF.Close()
		c := csv.NewReader(interimsF)
		c.FieldsPerRecord = 3

		var lines [][]string
		for {
			record, err := c.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			// If not finalized it survives
			if !removed[record[1]] {
				lines = append(lines, record)
			}
		}
		return lines, nil
	}()

	if err != nil {
		return err
	}

	// All interims are finalized now -> remove file.
	if len(lines) == 0 {
		return os.RemoveAll(interimsCSV)
	}

	// Overwrite old. It's save because we are in a transaction.

	f, err := os.Create(interimsCSV)
	if err != nil {
		return err
	}
	c := csv.NewWriter(f)

	if err := c.WriteAll(lines); err != nil {
		return f.Close()
	}

	c.Flush()
	err1 := c.Error()
	err2 := f.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

// readInterims scans a interims.csv file for matching
// iterim advisories. Its sorted with youngest
// first, so we can stop scanning if entries get too old.
func readInterims(interimsCSV string, years int) ([][2]string, error) {

	var tooOld func(time.Time) bool

	if years <= 0 {
		tooOld = func(time.Time) bool { return false }
	} else {
		from := time.Now().AddDate(-years, 0, 0)
		tooOld = func(t time.Time) bool { return t.Before(from) }
	}

	interimsF, err := os.Open(interimsCSV)
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
