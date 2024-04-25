// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"fmt"
	"strings"
	"testing"
)

const page0 = `<html>
<body>
	<a href="not-a-json">Not a JSON</a>
	<a href="link0.json">link0</a>
	<ol>
		<li><a href="link1.json">link1</a></li>
		<li><a href="link2.json">link1</a></li>
	</ol>
	<p>
	<div>
		<li><a href="link3.json">link1</a></li>
	</div>
	<p>
</body>
</html>`

func TestLinksOnPage(t *testing.T) {

	var links []string

	err := linksOnPage(
		strings.NewReader(page0),
		func(s string) error {
			if strings.HasSuffix(s, ".json") {
				links = append(links, s)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if l := len(links); l != 4 {
		t.Fatalf("Expected 4 links, go %d\n", l)
	}

	for i, link := range links {
		href := fmt.Sprintf("link%d.json", i)
		if href != link {
			t.Fatalf("Expected link '%s', got '%s'\n", href, link)
		}
	}
}
