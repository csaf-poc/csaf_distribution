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
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/csaf-poc/csaf_distribution/csaf"
	"github.com/csaf-poc/csaf_distribution/util"
)

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		err = nil
	}
	return false, err
}

func (p *processor) mirror(prv *provider) error {
	folder := filepath.Join(p.cfg.Folder, prv.Name)
	log.Printf("target: '%s'\n", folder)

	existsBefore, err := exists(folder)
	if err != nil {
		return err
	}
	log.Printf("exists before: %t\n", existsBefore)

	if !existsBefore {
		log.Println("-> fresh download")
		// TODO: Implement me!
	} else {
		log.Println("-> delta download")
		// TODO: Implement me!
	}

	c := p.cfg.httpClient(prv)
	doc, loc, err := p.locateProviderMetadata(c, prv.Domain)
	if err != nil {
		log.Printf("error: %v\n", err)
		return err
	}
	log.Printf("provider-metadata.json: %s\n", loc)
	base, err := url.Parse(loc)
	if err != nil {
		return err
	}

	expr := util.NewPathEval()
	rolie, err := expr.Eval("$.distributions[*].rolie.feeds", doc)
	if err != nil {
		return err
	}

	fs, hasRolie := rolie.([]interface{})
	hasRolie = hasRolie && len(fs) > 0

	if hasRolie {
		var feeds [][]csaf.Feed
		if err := util.ReMarshalJSON(&feeds, rolie); err != nil {
			return err
		}
		log.Printf("Found %d ROLIE feed(s).\n", len(feeds))

		for _, fs := range feeds {
			for i := range fs {
				feed := &fs[i]
				if feed.URL == nil {
					continue
				}
				up, err := url.Parse(string(*feed.URL))
				if err != nil {
					log.Printf("Invalid URL %s in feed: %v.", *feed.URL, err)
					continue
				}
				feedURL := base.ResolveReference(up).String()
				log.Printf("Feed URL: %s\n", feedURL)

				fb, err := util.BaseURL(feedURL)
				if err != nil {
					log.Printf("error: Invalid feed base URL '%s': %v\n", fb, err)
					continue
				}
				feedBaseURL, err := url.Parse(fb)
				if err != nil {
					log.Printf("error: Cannot parse feed base URL '%s': %v\n", fb, err)
					continue
				}

				res, err := c.Get(feedURL)
				if err != nil {
					log.Printf("error: Cannot get feed '%s'\n", err)
					continue
				}
				if res.StatusCode != http.StatusOK {
					log.Printf("error: Fetching %s failed. Status code %d (%s)",
						feedURL, res.StatusCode, res.Status)
					continue
				}
				rfeed, err := func() (*csaf.ROLIEFeed, error) {
					defer res.Body.Close()
					return csaf.LoadROLIEFeed(res.Body)
				}()
				if err != nil {
					log.Printf("Loading ROLIE feed failed: %v.", err)
					continue
				}
				files := resolveURLs(rfeed.Files(), feedBaseURL)
				for _, file := range files {
					log.Printf("-> %s\n", file)
				}
				// TODO: Process feed
			}
		}

	} else { // No rolie feeds
		// TODO: Implement me!
	}

	return nil
}
