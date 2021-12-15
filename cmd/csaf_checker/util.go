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
	"net/url"
	"regexp"
	"strings"
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

func basePath(p string) (string, error) {
	u, err := url.Parse(p)
	if err != nil {
		return "", err
	}
	ep := u.EscapedPath()
	if idx := strings.LastIndexByte(ep, '/'); idx != -1 {
		ep = ep[:idx+1]
	}
	user := u.User.String()
	if user != "" {
		user += "@"
	}
	if !strings.HasPrefix(ep, "/") {
		ep = "/" + ep
	}
	return u.Scheme + "://" + user + u.Host + ep, nil
}
