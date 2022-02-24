// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"log"
	"path/filepath"
)

func (w *worker) writeCSV(fname string, summaries []summary) error {

	log.Printf("CSV: %s\n", fname)
	// TODO: Implement me!

	return nil
}

func (w *worker) writeIndices() error {

	if len(w.summaries) == 0 || w.dir == "" {
		return nil
	}

	log.Printf("%s\n", w.dir)

	for label, summaries := range w.summaries {
		log.Printf("%s: %d\n", label, len(summaries))
		if err := w.writeCSV(filepath.Join(w.dir, label, "changes.csv"), summaries); err != nil {
			return err
		}
	}

	return nil
}
