// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package util

import (
	"net/url"
	"strings"
)

// BaseURL returns the base URL for a given URL p.
func BaseURL(p string) (string, error) {
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
