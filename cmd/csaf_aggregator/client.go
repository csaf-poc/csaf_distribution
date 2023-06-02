// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"errors"
	"io"
	"net/http"

	"github.com/csaf-poc/csaf_distribution/v2/util"
)

var errNotFound = errors.New("not found")

func downloadJSON(c util.Client, url string, found func(io.Reader) error) error {
	res, err := c.Get(url)
	if err != nil || res.StatusCode != http.StatusOK ||
		res.Header.Get("Content-Type") != "application/json" {
		// ignore this as it is expected.
		return errNotFound
	}
	return func() error {
		defer res.Body.Close()
		return found(res.Body)
	}()
}
