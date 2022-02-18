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
	"os"
	"path/filepath"
)

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		err = nil
	}
	return false, err
}

func (p *processor) mirror(prv *provider) error {
	folder := filepath.Join(p.cfg.Folder, prv.Name)
	log.Printf("target: '%s'\n", folder)

	existsBefore, err := exists(folder)
	if err != nil {
		return err
	}
	log.Printf("exists before: %t\n", existsBefore)

	if !existsBefore {
		log.Println("-> fresh download")
		// TODO: Implement me!
	} else {
		log.Println("-> delta download")
		// TODO: Implement me!
	}
	return nil
}
