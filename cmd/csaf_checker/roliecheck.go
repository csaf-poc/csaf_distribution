// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package main

import (
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/csaf-poc/csaf_distribution/v2/csaf"
	"github.com/csaf-poc/csaf_distribution/v2/util"
)

// rolieLabelChecker helps to check id advisories in ROLIE feeds
// are in there right TLP color.
type rolieLabelChecker struct {
	feedURL   string
	feedLabel csaf.TLPLabel

	advisories map[csaf.TLPLabel]util.Set[string]
}

// tlpLevel returns an inclusion order of TLP colors.
func tlpLevel(label csaf.TLPLabel) int {
	switch label {
	case csaf.TLPLabelWhite:
		return 1
	case csaf.TLPLabelGreen:
		return 2
	case csaf.TLPLabelAmber:
		return 3
	case csaf.TLPLabelRed:
		return 4
	default:
		return 0
	}
}

// tlpLabel returns the value of a none-nil pointer
// to a TLPLabel. If pointer is nil unlabeled is returned.
func tlpLabel(label *csaf.TLPLabel) csaf.TLPLabel {
	if label != nil {
		return *label
	}
	return csaf.TLPLabelUnlabeled
}

// add registers a given url to a label.
func (rlc *rolieLabelChecker) add(label csaf.TLPLabel, url string) {
	advs := rlc.advisories[label]
	if advs == nil {
		advs = util.Set[string]{}
		rlc.advisories[label] = advs
	}
	advs.Add(url)
}

// check tests if the TLP label of an advisory is used correctly.
func (rlc *rolieLabelChecker) check(
	p *processor,
	label csaf.TLPLabel,
	url string,
) {
	// Associate advisory label to urls.
	rlc.add(label, url)

	// If entry shows up in feed of higher tlp level, give out info or warning.
	rlc.checkRank(p, label, url)

	// Issue warnings or errors if the advisory is not protected properly.
	rlc.checkProtection(p, label, url)
}

// checkProtection tests if a given advisory has the right level
// of protection.
func (rlc *rolieLabelChecker) checkProtection(
	p *processor,
	label csaf.TLPLabel,
	url string,
) {
	switch {
	// If we are checking WHITE and we have a test client
	// and we get a status forbidden then the access is not open.
	case label == csaf.TLPLabelWhite:
		p.badWhitePermissions.use()
		// We only need to download it with an unauthorized client
		// if have not done it yet.
		if p.usedAuthorizedClient() {
			res, err := p.unauthorizedClient().Get(url)
			if err != nil {
				p.badWhitePermissions.error(
					"Unexpected Error %v when trying to fetch: %s", err, url)
			} else if res.StatusCode == http.StatusForbidden {
				p.badWhitePermissions.error(
					"Advisory %s of TLP level WHITE is access protected.", url)
			}
		}

	// If we are checking AMBER or above we need to download
	// the data again with the open client.
	// If this does not result in status forbidden the
	// server may be wrongly configured.
	case tlpLevel(label) >= tlpLevel(csaf.TLPLabelAmber):
		p.badAmberRedPermissions.use()
		// It is an error if we downloaded the advisory with
		// an unauthorized client.
		if !p.usedAuthorizedClient() {
			p.badAmberRedPermissions.error(
				"Advisory %s of TLP level %v is not properly access protected.",
				url, label)
		} else {
			// We came here by an authorized download which is okay.
			// So its bad if we can download it with an unauthorized client, too.
			res, err := p.unauthorizedClient().Get(url)
			if err != nil {
				p.badAmberRedPermissions.error(
					"Unexpected Error %v when trying to fetch: %s", err, url)
			} else if res.StatusCode == http.StatusOK {
				p.badAmberRedPermissions.error(
					"Advisory %s of TLP level %v is not properly access protected.",
					url, label)
			}
		}
	}
}

// checkRank tests if a given advisory is contained by the
// the right feed color.
func (rlc *rolieLabelChecker) checkRank(
	p *processor,
	label csaf.TLPLabel,
	url string,
) {
	switch advisoryRank, feedRank := tlpLevel(label), tlpLevel(rlc.feedLabel); {

	case advisoryRank < feedRank:
		if advisoryRank == 0 { // All kinds of 'UNLABELED'
			p.badROLIEFeed.info(
				"Found unlabeled advisory %q in feed %q.",
				url, rlc.feedURL)
		} else {
			p.badROLIEFeed.warn(
				"Found advisory %q labled TLP:%s in feed %q (TLP:%s).",
				url, label,
				rlc.feedURL, rlc.feedLabel)
		}

	case advisoryRank > feedRank:
		// Must not happen, give error
		p.badROLIEFeed.error(
			"%s of TLP level %s must not be listed in feed %s of TLP level %s",
			url, label, rlc.feedURL, rlc.feedLabel)
	}
}

// processROLIEFeeds goes through all ROLIE feeds and checks their
// integrity and completeness.
func (p *processor) processROLIEFeeds(feeds [][]csaf.Feed) error {

	base, err := url.Parse(p.pmdURL)
	if err != nil {
		return err
	}
	p.badROLIEFeed.use()

	advisories := map[*csaf.Feed][]csaf.AdvisoryFile{}

	// Phase 1: load all advisories urls.
	for _, fs := range feeds {
		for i := range fs {
			feed := &fs[i]
			if feed.URL == nil {
				continue
			}
			up, err := url.Parse(string(*feed.URL))
			if err != nil {
				p.badProviderMetadata.error("Invalid URL %s in feed: %v.", *feed.URL, err)
				continue
			}
			feedBase := base.ResolveReference(up)
			feedURL := feedBase.String()
			p.checkTLS(feedURL)

			advs, err := p.rolieFeedEntries(feedURL)
			if err != nil {
				if err != errContinue {
					return err
				}
				continue
			}
			advisories[feed] = advs
		}
	}

	p.labelChecker = &rolieLabelChecker{
		advisories: map[csaf.TLPLabel]util.Set[string]{},
	}

	// Phase 2: check for integrity.
	for _, fs := range feeds {
		for i := range fs {
			feed := &fs[i]
			if feed.URL == nil {
				continue
			}
			files := advisories[feed]
			if files == nil {
				continue
			}

			up, err := url.Parse(string(*feed.URL))
			if err != nil {
				p.badProviderMetadata.error("Invalid URL %s in feed: %v.", *feed.URL, err)
				continue
			}

			feedURL := base.ResolveReference(up)
			feedBase, err := util.BaseURL(feedURL)
			if err != nil {
				p.badProviderMetadata.error("Bad base path: %v", err)
				continue
			}

			label := tlpLabel(feed.TLPLabel)
			if err := p.categoryCheck(feedBase, label); err != nil {
				if err != errContinue {
					return err
				}
			}

			p.labelChecker.feedURL = feedURL.String()
			p.labelChecker.feedLabel = label

			// TODO: Issue a warning if we want check AMBER+ without an
			// authorizing client.

			// TODO: Complete criteria for requirement 4.

			if err := p.integrity(files, feedBase, rolieMask, p.badProviderMetadata.add); err != nil {
				if err != errContinue {
					return err
				}
			}
		}
	}

	// Phase 3: Check for completeness.

	hasSummary := util.Set[csaf.TLPLabel]{}

	var (
		hasUnlabeled = false
		hasWhite     = false
		hasGreen     = false
	)

	for _, fs := range feeds {
		for i := range fs {
			feed := &fs[i]
			if feed.URL == nil {
				continue
			}
			files := advisories[feed]
			if files == nil {
				continue
			}

			up, err := url.Parse(string(*feed.URL))
			if err != nil {
				p.badProviderMetadata.error("Invalid URL %s in feed: %v.", *feed.URL, err)
				continue
			}

			feedBase := base.ResolveReference(up)
			makeAbs := makeAbsolute(feedBase)
			label := tlpLabel(feed.TLPLabel)

			switch label {
			case csaf.TLPLabelUnlabeled:
				hasUnlabeled = true
			case csaf.TLPLabelWhite:
				hasWhite = true
			case csaf.TLPLabelGreen:
				hasGreen = true
			}

			reference := p.labelChecker.advisories[label]
			advisories := make(util.Set[string], len(reference))

			for _, adv := range files {
				u, err := url.Parse(adv.URL())
				if err != nil {
					p.badProviderMetadata.error(
						"Invalid URL %s in feed: %v.", *feed.URL, err)
					continue
				}
				advisories.Add(makeAbs(u).String())
			}
			if advisories.ContainsAll(reference) {
				hasSummary.Add(label)
			}
		}
	}

	if !hasWhite && !hasGreen && !hasUnlabeled {
		p.badROLIEFeed.error(
			"One ROLIE feed with a TLP:WHITE, TLP:GREEN or unlabeled tlp must exist, " +
				"but none were found.")
	}

	// Every TLP level with data should have at least on summary feed.
	for _, label := range []csaf.TLPLabel{
		csaf.TLPLabelUnlabeled,
		csaf.TLPLabelWhite,
		csaf.TLPLabelGreen,
		csaf.TLPLabelAmber,
		csaf.TLPLabelRed,
	} {
		if !hasSummary.Contains(label) && len(p.labelChecker.advisories[label]) > 0 {
			p.badROLIEFeed.warn(
				"ROLIE feed for TLP:%s has no accessible listed feed covering all advisories.",
				label)
		}
	}

	return nil
}

// categoryCheck checks for the existence of a feeds ROLIE category document and if it does,
// whether the category document contains distinguishing categories
func (p *processor) categoryCheck(folderURL string, label csaf.TLPLabel) error {
	labelname := strings.ToLower(string(label))
	urlrc := folderURL + "category-" + labelname + ".json"

	p.badROLIECategory.use()
	client := p.httpClient()
	res, err := client.Get(urlrc)
	if err != nil {
		p.badROLIECategory.error(
			"Cannot fetch rolie category document %s: %v", urlrc, err)
		return errContinue
	}
	if res.StatusCode != http.StatusOK {
		p.badROLIECategory.warn("Fetching %s failed. Status code %d (%s)",
			urlrc, res.StatusCode, res.Status)
		return errContinue
	}
	rolieCategory, err := func() (*csaf.ROLIECategoryDocument, error) {
		defer res.Body.Close()
		return csaf.LoadROLIECategoryDocument(res.Body)
	}()

	if err != nil {
		p.badROLIECategory.error(
			"Loading ROLIE category document %s failed: %v.", urlrc, err)
		return errContinue
	}
	if len(rolieCategory.Categories.Category) == 0 {
		p.badROLIECategory.warn(
			"No distinguishing categories in ROLIE category document: %s", urlrc)
	}
	return nil
}

// serviceCheck checks if a ROLIE service document exists and if it does,
// whether it contains all ROLIE feeds.
func (p *processor) serviceCheck(feeds [][]csaf.Feed) error {
	// service category document should be next to the pmd
	pmdURL, err := url.Parse(p.pmdURL)
	if err != nil {
		return err
	}
	baseURL, err := util.BaseURL(pmdURL)
	if err != nil {
		return err
	}
	urls := baseURL + "service.json"

	// load service document
	p.badROLIEService.use()

	client := p.httpClient()
	res, err := client.Get(urls)
	if err != nil {
		p.badROLIEService.error(
			"Cannot fetch rolie service document %s: %v", urls, err)
		return errContinue
	}
	if res.StatusCode != http.StatusOK {
		p.badROLIEService.warn("Fetching %s failed. Status code %d (%s)",
			urls, res.StatusCode, res.Status)
		return errContinue
	}

	rolieService, err := func() (*csaf.ROLIEServiceDocument, error) {
		defer res.Body.Close()
		return csaf.LoadROLIEServiceDocument(res.Body)
	}()

	if err != nil {
		p.badROLIEService.error(
			"Loading ROLIE service document %s failed: %v.", urls, err)
		return errContinue
	}

	// Build lists of all feeds in feeds and in the Service Document
	var (
		sfeeds = util.Set[string]{}
		ffeeds = util.Set[string]{}
	)
	for _, col := range rolieService.Service.Workspace {
		for _, fd := range col.Collection {
			sfeeds.Add(fd.HRef)
		}
	}
	for _, r := range feeds {
		for _, s := range r {
			ffeeds.Add(string(*s.URL))
		}
	}

	// Check if ROLIE Service Document contains exactly all ROLIE feeds
	if m1 := sfeeds.Difference(ffeeds).Keys(); len(m1) != 0 {
		sort.Strings(m1)
		p.badROLIEService.error(
			"The ROLIE service document %s contains nonexistent feed entries: %v", urls, m1)
	}
	if m2 := ffeeds.Difference(sfeeds).Keys(); len(m2) != 0 {
		sort.Strings(m2)
		p.badROLIEService.error(
			"The ROLIE service document %s is missing feed entries: %v", urls, m2)
	}

	// TODO: Check conformity with RFC8322
	return nil
}
