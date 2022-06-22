// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package csaf

import (
	"bufio"
	"log"
	"net/http"
	"net/url"

	"github.com/csaf-poc/csaf_distribution/util"
)

// AdvisoryFileProcessor implements the extraction of
// advisory file names from a given provider metadata.
type AdvisoryFileProcessor struct {
	client util.Client
	expr   *util.PathEval
	doc    interface{}
	base   *url.URL
}

// NewAdvisoryFileProcessor constructs an filename extractor
// for a given metadata document.
func NewAdvisoryFileProcessor(
	client util.Client,
	expr *util.PathEval,
	doc interface{},
	base *url.URL,
) *AdvisoryFileProcessor {
	return &AdvisoryFileProcessor{
		client: client,
		expr:   expr,
		doc:    doc,
		base:   base,
	}
}

// Process extracts the adivisory filenames and passes them with
// the corresponding label to fn.
func (afp *AdvisoryFileProcessor) Process(fn func(TLPLabel, []string) error) error {

	// Check if we have ROLIE feeds.
	rolie, err := afp.expr.Eval(
		"$.distributions[*].rolie.feeds", afp.doc)
	if err != nil {
		log.Printf("rolie check failed: %v\n", err)
		return err
	}

	fs, hasRolie := rolie.([]interface{})
	hasRolie = hasRolie && len(fs) > 0

	if hasRolie {
		var feeds [][]Feed
		if err := util.ReMarshalJSON(&feeds, rolie); err != nil {
			return err
		}
		log.Printf("Found %d ROLIE feed(s).\n", len(feeds))

		for _, feed := range feeds {
			if err := afp.processROLIE(feed, fn); err != nil {
				return err
			}
		}
	} else {
		// No rolie feeds -> try to load files from index.txt
		files, err := afp.loadIndex()
		if err != nil {
			return err
		}
		// XXX: Is treating as white okay? better look into the advisories?
		if err := fn(TLPLabelWhite, files); err != nil {
			return err
		}
	} // TODO: else scan directories?
	return nil
}

// loadIndex loads baseURL/index.txt and returns a list of files
// prefixed by baseURL/.
func (afp *AdvisoryFileProcessor) loadIndex() ([]string, error) {
	baseURL, err := util.BaseURL(afp.base)
	if err != nil {
		return nil, err
	}
	indexURL := baseURL + "/index.txt"
	resp, err := afp.client.Get(indexURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var lines []string

	scanner := bufio.NewScanner(resp.Body)

	for scanner.Scan() {
		lines = append(lines, baseURL+"/"+scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func (afp *AdvisoryFileProcessor) processROLIE(
	labeledFeeds []Feed,
	fn func(TLPLabel, []string) error,
) error {
	for i := range labeledFeeds {
		feed := &labeledFeeds[i]
		if feed.URL == nil {
			continue
		}
		up, err := url.Parse(string(*feed.URL))
		if err != nil {
			log.Printf("Invalid URL %s in feed: %v.", *feed.URL, err)
			continue
		}
		feedURL := afp.base.ResolveReference(up)
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

		res, err := afp.client.Get(feedURL.String())
		if err != nil {
			log.Printf("error: Cannot get feed '%s'\n", err)
			continue
		}
		if res.StatusCode != http.StatusOK {
			log.Printf("error: Fetching %s failed. Status code %d (%s)",
				feedURL, res.StatusCode, res.Status)
			continue
		}
		rfeed, err := func() (*ROLIEFeed, error) {
			defer res.Body.Close()
			return LoadROLIEFeed(res.Body)
		}()
		if err != nil {
			log.Printf("Loading ROLIE feed failed: %v.", err)
			continue
		}

		// Extract the adivisory URLs from the feed.
		var files []string
		rfeed.Links(func(l *Link) {
			if l.Rel != "self" {
				return
			}
			href, err := url.Parse(l.HRef)
			if err != nil {
				log.Printf("error: Invalid URL '%s': %v", l.HRef, err)
				return
			}
			files = append(files, feedBaseURL.ResolveReference(href).String())
		})

		var label TLPLabel
		if feed.TLPLabel != nil {
			label = *feed.TLPLabel
		} else {
			label = "unknown"
		}

		if err := fn(label, files); err != nil {
			return err
		}
	}
	return nil
}
