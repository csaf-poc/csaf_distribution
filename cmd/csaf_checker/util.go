// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package main

import (
	"bufio"
	"encoding/hex"
	"io"
	"regexp"
)

var hexRe = regexp.MustCompile(`^([[:xdigit:]]+)`)

func hashFromReader(r io.Reader) ([]byte, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if m := hexRe.FindStringSubmatch(scanner.Text()); m != nil {
			return hex.DecodeString(m[1])
		}
	}
	return nil, scanner.Err()
}
