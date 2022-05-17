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
	"net/http"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

func (p *processor) linksOnPageURL(baseDir string) ([]string, error) {

	base, err := url.Parse(baseDir)
	if err != nil {
		return nil, err
	}

	client := p.httpClient()
	p.checkTLS(baseDir)
	res, err := client.Get(baseDir)

	p.badDirListings.use()

	if err != nil {
		p.badDirListings.add("Fetching %s failed: %v", base, err)
		return nil, errContinue
	}
	if res.StatusCode != http.StatusOK {
		p.badDirListings.add("Fetching %s failed. Status code %d (%s)",
			base, res.StatusCode, res.Status)
		return nil, errContinue
	}

	defer res.Body.Close()

	// Links may be relative
	return linksOnPage(res.Body, func(link string) (string, error) {
		u, err := url.Parse(link)
		if err != nil {
			return "", err
		}
		return base.ResolveReference(u).String(), nil
	})

}

func linksOnPage(r io.Reader, resolve func(string) (string, error)) ([]string, error) {

	doc, err := goquery.NewDocumentFromReader(r)
	if err != nil {
		return nil, err
	}

	var links []string

	doc.Find("a").Each(func(_ int, s *goquery.Selection) {
		if err != nil {
			return
		}
		if link, ok := s.Attr("href"); ok {
			// Only care for JSON files here.
			if !strings.HasSuffix(link, ".json") {
				return
			}
			if link, err = resolve(link); err == nil {
				links = append(links, link)
			}
		}
	})

	return links, err
}
