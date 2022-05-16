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
	"net/url"
)

// resolveURLs resolves a list of URLs urls against a base URL base.
func resolveURLs(urls []string, base *url.URL) []string {
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		p, err := url.Parse(u)
		if err != nil {
			log.Printf("error: Invalid URL '%s': %v\n", u, err)
			continue
		}
		out = append(out, base.ResolveReference(p).String())
	}
	return out
}
