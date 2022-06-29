// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/csaf-poc/csaf_distribution/csaf"
	"github.com/csaf-poc/csaf_distribution/util"
)

func (c *controller) extendROLIE(
	folder string,
	newCSAF string,
	t tlp,
	ex *csaf.AdvisorySummary,
) error {
	// Load the feed
	ts := string(t)
	feedName := "csaf-feed-tlp-" + ts + ".json"

	feed := filepath.Join(folder, feedName)
	rolie, err := loadROLIEFeed(feed)
	if err != nil {
		return err
	}

	feedURL := csaf.JSONURL(
		c.cfg.CanonicalURLPrefix +
			"/.well-known/csaf/" + ts + "/" + feedName)

	tlpLabel := csaf.TLPLabel(strings.ToUpper(ts))

	// Create new if does not exists.
	if rolie == nil {
		rolie = &csaf.ROLIEFeed{
			Feed: csaf.FeedData{
				ID:    "csaf-feed-tlp-" + ts,
				Title: "CSAF feed (TLP:" + string(tlpLabel) + ")",
				Link: []csaf.Link{{
					Rel:  "self",
					HRef: string(feedURL),
				}},
				Category: []csaf.ROLIECategory{{
					Scheme: "urn:ietf:params:rolie:category:information-type",
					Term:   "csaf",
				}},
			},
		}
	}

	rolie.Feed.Updated = csaf.TimeStamp(time.Now().UTC())

	year := strconv.Itoa(ex.InitialReleaseDate.Year())

	csafURL := c.cfg.CanonicalURLPrefix +
		"/.well-known/csaf/" + ts + "/" + year + "/" + newCSAF

	e := rolie.EntryByID(ex.ID)
	if e == nil {
		e = &csaf.Entry{ID: ex.ID}
		rolie.Feed.Entry = append(rolie.Feed.Entry, e)
	}

	e.Titel = ex.Title
	e.Published = csaf.TimeStamp(ex.InitialReleaseDate)
	e.Updated = csaf.TimeStamp(ex.CurrentReleaseDate)
	e.Link = []csaf.Link{
		{Rel: "self", HRef: csafURL},
		{Rel: "hash", HRef: csafURL + ".sha256"},
		{Rel: "hash", HRef: csafURL + ".sha512"},
		{Rel: "signature", HRef: csafURL + ".asc"},
	}
	e.Format = csaf.Format{
		Schema:  "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json",
		Version: "2.0",
	}
	e.Content = csaf.Content{
		Type: "application/json",
		Src:  csafURL,
	}
	if ex.Summary != "" {
		e.Summary = &csaf.Summary{Content: ex.Summary}
	} else {
		e.Summary = nil
	}

	// Sort by descending updated order.
	rolie.SortEntriesByUpdated()

	// Store the feed
	return util.WriteToFile(feed, rolie)
}

// loadROLIEFeed loads a ROLIE feed from file if its exists.
// Returns nil if the file does not exists.
func loadROLIEFeed(feed string) (*csaf.ROLIEFeed, error) {
	f, err := os.Open(feed)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	return csaf.LoadROLIEFeed(f)
}
