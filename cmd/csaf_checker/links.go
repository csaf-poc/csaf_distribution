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

	"github.com/PuerkitoBio/goquery"
	"github.com/csaf-poc/csaf_distribution/util"
)

type (
	pageContent struct {
		err   error
		links map[string]struct{}
	}
	pages map[string]*pageContent
)

func (pgs pages) listed(path string, pro *processor) (bool, error) {
	base, err := util.BaseURL(path)
	if err != nil {
		return false, err
	}

	content := pgs[base]
	if content != nil { // already loaded
		if content.err != nil {
			return false, nil
		}
		_, ok := content.links[path]
		return ok, nil
	}

	baseURL, err := url.Parse(base)
	if err != nil {
		return false, err
	}

	// load page
	client := pro.httpClient()
	pro.checkTLS(base)
	res, err := client.Get(base)

	pro.badDirListings.use()

	if err != nil {
		pro.badDirListings.add("Fetching %s failed: %v", base, err)
		return false, errContinue
	}
	if res.StatusCode != http.StatusOK {
		pro.badDirListings.add("Fetching %s failed. Status code %d (%s)",
			base, res.StatusCode, res.Status)
		return false, errContinue
	}

	content = &pageContent{
		links: map[string]struct{}{},
	}

	pgs[base] = content

	// Build link index for this page.

	if err := func() error {
		defer res.Body.Close()
		return linksOnPage(res.Body, func(link string) error {
			u, err := url.Parse(link)
			if err != nil {
				return err
			}
			// Links may be relative
			abs := baseURL.ResolveReference(u).String()
			content.links[abs] = struct{}{}
			return nil
		})
	}(); err != nil {
		return false, errContinue
	}

	_, ok := content.links[path]
	return ok, nil
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
