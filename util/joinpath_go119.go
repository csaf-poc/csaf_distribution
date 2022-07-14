// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

//go:build go1.19

package util

import "net/url"

func JoinURLPath(u *url.URL, elem ...string) *URL {
	return u.JoinPath(elem...)
}
