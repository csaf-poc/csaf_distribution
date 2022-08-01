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
	"strings"

	"github.com/csaf-poc/csaf_distribution/util"
)

// AdvisoryFile constructs the urls of a remote file.
type AdvisoryFile interface {
	URL() string
	SHA256URL() string
	SHA512URL() string
	SignURL() string
}

// PlainAdvisoryFile is a simple implementation of checkFile.
// The hash and signature files are directly constructed by extending
// the file name.
type PlainAdvisoryFile string

// URL returns the URL of this advisory.
func (paf PlainAdvisoryFile) URL() string { return string(paf) }

// SHA256URL returns the URL of SHA256 hash file of this advisory.
func (paf PlainAdvisoryFile) SHA256URL() string { return string(paf) + ".sha256" }

// SHA512URL returns the URL of SHA512 hash file of this advisory.
func (paf PlainAdvisoryFile) SHA512URL() string { return string(paf) + ".sha512" }

// SignURL returns the URL of signature file of this advisory.
func (paf PlainAdvisoryFile) SignURL() string { return string(paf) + ".asc" }

// HashedAdvisoryFile is a more involed version of checkFile.
// Here each component can be given explicitly.
// If a component is not given it is constructed by
// extending the first component.
type HashedAdvisoryFile [4]string

func (haf HashedAdvisoryFile) name(i int, ext string) string {
	if haf[i] != "" {
		return haf[i]
	}
	return haf[0] + ext
}

// URL returns the URL of this advisory.
func (haf HashedAdvisoryFile) URL() string { return haf[0] }

// SHA256URL returns the URL of SHA256 hash file of this advisory.
func (haf HashedAdvisoryFile) SHA256URL() string { return haf.name(1, ".sha256") }

// SHA512URL returns the URL of SHA512 hash file of this advisory.
func (haf HashedAdvisoryFile) SHA512URL() string { return haf.name(2, ".sha512") }

// SignURL returns the URL of signature file of this advisory.
func (haf HashedAdvisoryFile) SignURL() string { return haf.name(3, ".asc") }

// AdvisoryFileProcessor implements the extraction of
// advisory file names from a given provider metadata.
type AdvisoryFileProcessor struct {
	client util.Client
	expr   *util.PathEval
	doc    interface{}
	base   *url.URL
	log    func(format string, args ...interface{})
}

// NewAdvisoryFileProcessor constructs an filename extractor
// for a given metadata document.
func NewAdvisoryFileProcessor(
	client util.Client,
	expr *util.PathEval,
	doc interface{},
	base *url.URL,
	log func(format string, args ...interface{}),
) *AdvisoryFileProcessor {
	return &AdvisoryFileProcessor{
		client: client,
		expr:   expr,
		doc:    doc,
		base:   base,
		log:    log,
	}
}

// empty checks if list of strings contains at least one none empty string.
func empty(arr []string) bool {
	for _, s := range arr {
		if s != "" {
			return false
		}
	}
	return true
}

// Process extracts the adivisory filenames and passes them with
// the corresponding label to fn.
func (afp *AdvisoryFileProcessor) Process(
	fn func(TLPLabel, []AdvisoryFile) error,
) error {
	lg := afp.log
	if lg == nil {
		lg = func(format string, args ...interface{}) {
			log.Printf("AdvisoryFileProcessor.Process: "+format, args...)
		}
	}

	// Check if we have ROLIE feeds.
	rolie, err := afp.expr.Eval(
		"$.distributions[*].rolie.feeds", afp.doc)
	if err != nil {
		lg("rolie check failed: %v\n", err)
		return err
	}

	fs, hasRolie := rolie.([]interface{})
	hasRolie = hasRolie && len(fs) > 0

	if hasRolie {
		var feeds [][]Feed
		if err := util.ReMarshalJSON(&feeds, rolie); err != nil {
			return err
		}
		lg("Found %d ROLIE feed(s).\n", len(feeds))

		for _, feed := range feeds {
			if err := afp.processROLIE(feed, fn); err != nil {
				return err
			}
		}
	} else {
		// No rolie feeds -> try to load files from index.txt

		directoryURLs, err := afp.expr.Eval(
			"$.distributions[*].directory_url", afp.doc)

		var dirURLs []string

		if err != nil {
			lg("extracting directory URLs failed: %v\n", err)
		} else {
			var ok bool
			dirURLs, ok = util.AsStrings(directoryURLs)
			if !ok {
				lg("directory_urls are not strings.\n")
			}
		}

		// Not found -> fall back to PMD url
		if empty(dirURLs) {
			baseURL, err := util.BaseURL(afp.base)
			if err != nil {
				return err
			}
			dirURLs = []string{baseURL}
		}

		for _, base := range dirURLs {
			if base == "" {
				continue
			}

			files, err := afp.loadIndex(base, lg)
			if err != nil {
				return err
			}
			// XXX: Is treating as white okay? better look into the advisories?
			if err := fn(TLPLabelWhite, files); err != nil {
				return err
			}
		}
	} // TODO: else scan directories?
	return nil
}

// loadIndex loads baseURL/index.txt and returns a list of files
// prefixed by baseURL/.
func (afp *AdvisoryFileProcessor) loadIndex(
	baseURL string,
	lg func(string, ...interface{}),
) ([]AdvisoryFile, error) {

	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	indexURL := util.JoinURLPath(base, "index.txt").String()
	resp, err := afp.client.Get(indexURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var files []AdvisoryFile

	scanner := bufio.NewScanner(resp.Body)

	for line := 1; scanner.Scan(); line++ {
		u := scanner.Text()
		if _, err := url.Parse(u); err != nil {
			lg("index.txt contains invalid URL %q in line %d", u, line)
			continue
		}
		files = append(files,
			PlainAdvisoryFile(util.JoinURLPath(base, u).String()))
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return files, nil
}

func (afp *AdvisoryFileProcessor) processROLIE(
	labeledFeeds []Feed,
	fn func(TLPLabel, []AdvisoryFile) error,
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

		var files []AdvisoryFile

		resolve := func(u string) string {
			if u == "" {
				return ""
			}
			p, err := url.Parse(u)
			if err != nil {
				log.Printf("error: Invalid URL '%s': %v", u, err)
				return ""
			}
			return feedBaseURL.ResolveReference(p).String()
		}

		rfeed.Entries(func(entry *Entry) {

			var self, sha256, sha512, sign string

			for i := range entry.Link {
				link := &entry.Link[i]
				lower := strings.ToLower(link.HRef)
				switch link.Rel {
				case "self":
					self = resolve(link.HRef)
				case "signature":
					sign = resolve(link.HRef)
				case "hash":
					switch {
					case strings.HasSuffix(lower, ".sha256"):
						sha256 = resolve(link.HRef)
					case strings.HasSuffix(lower, ".sha512"):
						sha512 = resolve(link.HRef)
					}
				}
			}

			if self == "" {
				return
			}

			var file AdvisoryFile

			if sha256 != "" || sha512 != "" || sign != "" {
				file = HashedAdvisoryFile{self, sha256, sha512, sign}
			} else {
				file = PlainAdvisoryFile(self)
			}

			files = append(files, file)
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
