// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"
)

func (w *worker) writeCSV(fname string, summaries []summary) error {

	// Do not sort in-place.
	ss := make([]summary, len(summaries))
	copy(ss, summaries)

	sort.SliceStable(ss, func(i, j int) bool {
		return ss[i].summary.CurrentReleaseDate.After(
			ss[j].summary.CurrentReleaseDate)
	})

	f, err := os.Create(fname)
	if err != nil {
		return err
	}
	out := csv.NewWriter(f)

	record := make([]string, 2)

	for i := range ss {
		s := &ss[i]
		record[0] =
			s.summary.CurrentReleaseDate.Format(time.RFC3339)
		record[1] =
			strconv.Itoa(s.summary.InitialReleaseDate.Year()) + "/" + s.filename
		if err := out.Write(record); err != nil {
			f.Close()
			return err
		}
	}
	out.Flush()
	err1 := out.Error()
	err2 := f.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

func (w *worker) writeIndex(fname string, summaries []summary) error {

	f, err := os.Create(fname)
	if err != nil {
		return err
	}
	out := bufio.NewWriter(f)
	for i := range summaries {
		s := &summaries[i]
		fmt.Fprintf(
			out, "%d/%s\n",
			s.summary.InitialReleaseDate.Year(),
			s.filename)
	}
	err1 := out.Flush()
	err2 := f.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

func (w *worker) writeIndices() error {

	if len(w.summaries) == 0 || w.dir == "" {
		return nil
	}

	for label, summaries := range w.summaries {
		log.Printf("%s: %d\n", label, len(summaries))
		csvFile := filepath.Join(w.dir, label, "changes.csv")
		if err := w.writeCSV(csvFile, summaries); err != nil {
			return err
		}
		indexFile := filepath.Join(w.dir, label, "index.txt")
		if err := w.writeIndex(indexFile, summaries); err != nil {
			return err
		}
	}

	return nil
}
