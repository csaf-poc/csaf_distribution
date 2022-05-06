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
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/csaf-poc/csaf_distribution/util"
)

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
