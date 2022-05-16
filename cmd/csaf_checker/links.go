// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"io"

	"github.com/PuerkitoBio/goquery"
)

func linksOnPage(r io.Reader) ([]string, error) {

	doc, err := goquery.NewDocumentFromReader(r)
	if err != nil {
		return nil, err
	}

	var links []string

	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		if link, ok := s.Attr("href"); ok {
			links = append(links, link)
		}
	})

	return links, nil
}
