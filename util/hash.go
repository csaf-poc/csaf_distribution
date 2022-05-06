// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package util

import (
	"bufio"
	"encoding/hex"
	"io"
	"os"
	"regexp"
)

var hexRe = regexp.MustCompile(`^([[:xdigit:]]+)`)

// HashFromReader reads a base 16 coded hash sum from a reader.
func HashFromReader(r io.Reader) ([]byte, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if m := hexRe.FindStringSubmatch(scanner.Text()); m != nil {
			return hex.DecodeString(m[1])
		}
	}
	return nil, scanner.Err()
}

// HashFromFile reads a base 16 coded hash sum from a file.
func HashFromFile(fname string) ([]byte, error) {
	f, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return HashFromReader(f)
}
