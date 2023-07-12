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

// labelChecker helps to check id advisories in ROLIE feeds
// are in there right TLP color.
type labelChecker struct {
	feedURL   string
	feedLabel csaf.TLPLabel

	advisories map[csaf.TLPLabel]util.Set[string]
}

// reset brings the checker back to an initial state.
func (lc *labelChecker) reset() {
	lc.feedLabel = ""
	lc.feedURL = ""
	lc.advisories = map[csaf.TLPLabel]util.Set[string]{}
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

// evaluateTLP extracts the TLP label from a given document and
// calls upon functions further checking for mistakes in access-protection
// or label assignment between feed and advisory
func (p *processor) evaluateTLP(doc any, name string) {
	// extract document
	document, err := p.expr.Eval(
		`$.document`, doc)
	if err != nil {
		p.badROLIEFeed.error(
			"Extracting 'tlp level' from %s failed: %v",
			name, err)
		return
	}
	// extract advisory TLP label
	advisoryLabel := extractTLP(document)
	// If the client has no authorization it shouldn't be able
	// to access TLP:AMBER or TLP:RED advisories
	if !p.opts.protectedAccess() &&
		(advisoryLabel == csaf.TLPLabelAmber || advisoryLabel == csaf.TLPLabelRed) {
		p.badAmberRedPermissions.use()
		p.badAmberRedPermissions.error(
			"Advisory %s of TLP level %v is not access protected.",
			name, advisoryLabel)
	}

	if p.opts.protectedAccess() && (advisoryLabel == csaf.TLPLabelWhite) {
		p.badWhitePermissions.use()
		identifier, err := p.extractAdvisoryIdentifier(doc, name)
		// If there is a valid identifier,
		// sort it into the processor for later evaluation
		if err == nil {
			p.sortIntoWhiteAdvs(identifier)
		}
	}
	p.labelChecker.check(p, advisoryLabel, name)
}

// add registers a given url to a label.
func (lc *labelChecker) add(label csaf.TLPLabel, url string) {
	advs := lc.advisories[label]
	if advs == nil {
		advs = util.Set[string]{}
		lc.advisories[label] = advs
	}
	advs.Add(url)
}

// check tests if the TLP label of an advisory is used correctly.
func (lc *labelChecker) check(
	p *processor,
	label csaf.TLPLabel,
	url string,
) {
	// Associate advisory label to urls.
	lc.add(label, url)

	// If entry shows up in feed of higher tlp level, give out info or warning.
	lc.checkRank(p, label, url)

	// Issue warnings or errors if the advisory is not protected properly.
	lc.checkProtection(p, label, url)
}

// checkProtection tests if a given advisory has the right level
// of protection.
func (lc *labelChecker) checkProtection(
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
				p.badWhitePermissions.warn(
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
func (lc *labelChecker) checkRank(
	p *processor,
	label csaf.TLPLabel,
	url string,
) {
	if lc.feedLabel == "" {
		return
	}

	switch advisoryRank, feedRank := tlpLevel(label), tlpLevel(lc.feedLabel); {

	case advisoryRank < feedRank:
		if advisoryRank == 0 { // All kinds of 'UNLABELED'
			p.badROLIEFeed.info(
				"Found unlabeled advisory %q in feed %q.",
				url, lc.feedURL)
		} else {
			p.badROLIEFeed.warn(
				"Found advisory %q labled TLP:%s in feed %q (TLP:%s).",
				url, label,
				lc.feedURL, lc.feedLabel)
		}

	case advisoryRank > feedRank:
		// Must not happen, give error
		p.badROLIEFeed.error(
			"%s of TLP level %s must not be listed in feed %s of TLP level %s",
			url, label, lc.feedURL, lc.feedLabel)
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

// extractTLP tries to extract a valid TLP label from an advisory
// Returns "UNLABELED" if it does not exist, the label otherwise
func extractTLP(tlpa any) csaf.TLPLabel {
	if document, ok := tlpa.(map[string]any); ok {
		if distri, ok := document["distribution"]; ok {
			if distribution, ok := distri.(map[string]any); ok {
				if tlp, ok := distribution["tlp"]; ok {
					if label, ok := tlp.(map[string]any); ok {
						if labelstring, ok := label["label"].(string); ok {
							return csaf.TLPLabel(labelstring)
						}
					}
				}
			}
		}
	}
	return csaf.TLPLabelUnlabeled
}

// Extract document/publisher/namespace and document/tracking/id from advisory
// and save it in an identifier
func (p *processor) extractAdvisoryIdentifier(doc any, name string) (identifier, error) {
	var identifier identifier
	namespace, err := p.expr.Eval(`$.document.publisher.namespace`, doc)
	if err != nil {
		p.badWhitePermissions.error(
			"Extracting 'namespace' from %s failed: %v", name, err)
		return identifier, err
	}

	id, err := p.expr.Eval(`$.document.tracking.id`, doc)
	if err != nil {
		p.badWhitePermissions.error(
			"Extracting 'id' from %s failed: %v", name, err)
		return identifier, err
	}
	identifier.name = name
	identifier.namespace = namespace.(string) // TODO: Check type assertion!
	identifier.id = id.(string)               // TODO: Check type assertion!
	return identifier, nil
}

// sortIntoWhiteAdvs sorts identifiers into protected or free within the processor
func (p *processor) sortIntoWhiteAdvs(ide identifier) {
	// Currently, if there is no openClient, this means the advisory was
	// freely accessible. TODO: Make viable without labelchecker.
	if p.usedAuthorizedClient() {
		p.whiteAdvisories.free = append(p.whiteAdvisories.free, ide)
		return
	}
	res, err := p.unauthClient.Get(ide.name)
	if err != nil {
		p.badWhitePermissions.error(
			"Unexpected Error %v when trying to fetch: %s", err, ide.name)
	} else if res.StatusCode == http.StatusOK {
		p.whiteAdvisories.free = append(p.whiteAdvisories.free, ide)
	} else if res.StatusCode == http.StatusForbidden {
		p.whiteAdvisories.protected = append(p.whiteAdvisories.protected, ide)
	} else {
		p.badWhitePermissions.error(
			"Unexpected Server response %v when trying to fetch %s", res.StatusCode, ide.name)
	}
}
