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
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/csaf-poc/csaf_distribution/csaf"
	"github.com/csaf-poc/csaf_distribution/util"
)

func (w *worker) handleROLIE(
	rolie interface{},
	process func(*csaf.Feed, []string) error,
) error {
	base, err := url.Parse(w.loc)
	if err != nil {
		return err
	}
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

			res, err := w.client.Get(feedURL)
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
			if err := process(feed, files); err != nil {
				return err
			}
		}
	}
	return nil
}

// mirrorAllowed checks if mirroring is allowed.
func (w *worker) mirrorAllowed() bool {
	if a, err := w.expr.Eval(
		"$.mirror_on_CSAF_aggregators",
		w.metadataProvider,
	); err == nil {
		if ma, ok := a.(bool); ok {
			return ma
		}
	}
	return true
}

func (w *worker) mirror() error {

	// Check if we are allowed to mirror this domain.
	//if false && !w.mirrorAllowed() {
	if !w.mirrorAllowed() {
		return fmt.Errorf("No mirroring of '%s' allowed.\n", w.provider.Name)
	}

	folder := filepath.Join(w.cfg.Folder, w.provider.Name)
	log.Printf("target: '%s'\n", folder)

	existsBefore, err := util.PathExists(folder)
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

	// Check if we have ROLIE feeds.
	rolie, err := w.expr.Eval("$.distributions[*].rolie.feeds", w.metadataProvider)
	if err != nil {
		log.Printf("rolie check failed: %v\n", err)
		return err
	}

	fs, hasRolie := rolie.([]interface{})
	hasRolie = hasRolie && len(fs) > 0

	if hasRolie {
		if err := w.handleROLIE(rolie, w.mirrorFiles); err != nil {
			return err
		}
		return errors.New("not implemented, yet")
	}
	// No rolie feeds
	// TODO: Implement me!

	return errors.New("not implemented, yet")
}

func (w *worker) mirrorFiles(feed *csaf.Feed, files []string) error {
	label := "unknown"
	if feed.TLPLabel != nil {
		label = strings.ToLower(string(*feed.TLPLabel))
	}

	dir, err := w.createDir()
	if err != nil {
		return err
	}

	ndir, err := util.MakeUniqDir(filepath.Join(dir, label))
	if err != nil {
		return err
	}

	log.Printf("New directory: %s\n", ndir)

	// TODO: Process feed files
	for _, file := range files {
		log.Printf("%s: %s\n", label, file)
	}
	return nil
}
