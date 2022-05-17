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
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

var yearFolder = regexp.MustCompile(`.*/?\d{4}/?$`)

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

	var (
		subDirs []string
		files   []string
	)
	if err := func() error {
		defer res.Body.Close()
		return linksOnPage(res.Body, func(link string) error {
			u, err := url.Parse(link)
			if err != nil {
				return err
			}
			// Links may be relative
			abs := base.ResolveReference(u).String()
			switch {
			case yearFolder.MatchString(link):
				subDirs = append(subDirs, abs)
			case strings.HasSuffix(link, ".json"):
				files = append(files, abs)
			}
			return nil
		})
	}(); err != nil {
		return nil, err
	}

	// If we do not have sub folders, return links from this level.
	if len(subDirs) == 0 {
		return files, nil
	}

	// Descent into folders
	for _, sub := range subDirs {
		p.checkTLS(sub)
		res, err := client.Get(sub)
		if err != nil {
			p.badDirListings.add("Fetching %s failed: %v", sub, err)
			return nil, errContinue
		}
		if res.StatusCode != http.StatusOK {
			p.badDirListings.add("Fetching %s failed. Status code %d (%s)",
				base, res.StatusCode, res.Status)
			return nil, errContinue
		}
		if err := func() error {
			defer res.Body.Close()
			return linksOnPage(res.Body, func(link string) error {
				u, err := url.Parse(link)
				if err != nil {
					return err
				}
				// Links may be relative
				abs := base.ResolveReference(u).String()
				// Only collect json files in this sub folder
				if strings.HasSuffix(link, ".json") {
					files = append(files, abs)
				}
				return nil
			})
		}(); err != nil {
			return nil, err
		}
	}

	return files, nil
}

func linksOnPage(r io.Reader, visit func(string) error) error {

	doc, err := goquery.NewDocumentFromReader(r)
	if err != nil {
		return err
	}

	doc.Find("a").Each(func(_ int, s *goquery.Selection) {
		if err != nil {
			return
		}
		if link, ok := s.Attr("href"); ok {
			err = visit(link)
		}
	})

	return err
}
