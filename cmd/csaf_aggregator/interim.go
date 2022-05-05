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
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/csaf-poc/csaf_distribution/util"
)

func loadIndexFromReader(r io.Reader, accept func(string) bool) ([]string, error) {
	var files []string
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		file := scanner.Text()
		if accept(file) {
			files = append(files, file)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return files, nil
}

func scanForInterimFiles(base string, years int) ([]string, error) {

	if years == 0 {
		years = 10_000
	}

	from := time.Now().Year() - years

	pe := util.NewPathEval()

	accept := func(fname string) bool {
		dname := filepath.Dir(fname)
		year, err := strconv.Atoi(dname)
		if err != nil {
			return false
		}

		if year < from {
			return false
		}

		fn := filepath.Join(base, fname)
		f, err := os.Open(fn)
		if err != nil {
			return false
		}
		defer f.Close()

		var doc interface{}
		if err := json.NewDecoder(f).Decode(&doc); err != nil {
			return false
		}

		const interimExpr = `$.document.status"`

		var status string
		return pe.Extract(interimExpr, util.StringMatcher(&status), doc) == nil &&
			status == "interim"
	}

	indexF, err := os.Open(filepath.Join(base, "index.txt"))
	if err != nil {
		return nil, err
	}
	defer indexF.Close()

	return loadIndexFromReader(indexF, accept)
}
