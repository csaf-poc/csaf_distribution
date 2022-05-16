// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"os"

	"github.com/csaf-poc/csaf_distribution/util"
)

func writeHashedFile(fname, name string, data []byte, armored string) error {
	// Write the file itself.
	if err := os.WriteFile(fname, data, 0644); err != nil {
		return err
	}
	// Write SHA256 sum.
	if err := util.WriteHashToFile(fname+".sha256", name, sha256.New(), data); err != nil {
		return err
	}
	// Write SHA512 sum.
	if err := util.WriteHashToFile(fname+".sha512", name, sha512.New(), data); err != nil {
		return err
	}
	// Write signature.
	if err := os.WriteFile(fname+".asc", []byte(armored), 0644); err != nil {
		return err
	}
	return nil
}
