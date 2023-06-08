// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package main

import (
	"net/url"

	"github.com/csaf-poc/csaf_distribution/v2/csaf"
	"github.com/csaf-poc/csaf_distribution/v2/util"
)

// rolieLabelChecker helps to check id advisories in ROLIE feeds
// are in there right TLP color.
type rolieLabelChecker struct {
	feedURL   string
	feedLabel csaf.TLPLabel

	advisories map[csaf.TLPLabel]map[string]struct{}
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

// check tests if in advisory is in the right TLP color of the
// currently tested feed.
func (ca *rolieLabelChecker) check(
	p *processor,
	advisoryLabel csaf.TLPLabel,
	advisory string,
) {
	// Assign int to tlp levels for easy comparison
	var (
		advisoryRank = tlpLevel(advisoryLabel)
		feedRank     = tlpLevel(ca.feedLabel)
	)

	// Associate advisory label to urls.
	advs := ca.advisories[advisoryLabel]
	if advs == nil {
		advs = make(map[string]struct{})
		ca.advisories[advisoryLabel] = advs
	}
	advs[advisory] = struct{}{}

	// If entry shows up in feed of higher tlp level,
	// give out info or warning
	switch {
	case advisoryRank < feedRank:
		if advisoryRank == 0 { // All kinds of 'UNLABELED'
			p.badROLIEfeed.info(
				"Found unlabeled advisory %q in feed %q.",
				advisory, ca.feedURL)
		} else {
			p.badROLIEfeed.warn(
				"Found advisory %q labled TLP:%s in feed %q (TLP:%s).",
				advisory, advisoryLabel,
				ca.feedURL, ca.feedLabel)
		}

	case advisoryRank > feedRank:
		// Must not happen, give error
		p.badROLIEfeed.error(
			"%s of TLP level %s must not be listed in feed %s of TLP level %s",
			advisory, advisoryLabel, ca.feedURL, ca.feedLabel)
	}
}

// processROLIEFeeds goes through all ROLIE feeds and checks there
// integriry and completeness.
func (p *processor) processROLIEFeeds(feeds [][]csaf.Feed) error {

	base, err := url.Parse(p.pmdURL)
	if err != nil {
		return err
	}
	p.badROLIEfeed.use()

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

			p.labelChecker = &rolieLabelChecker{
				feedURL:    feedURL.String(),
				feedLabel:  label,
				advisories: map[csaf.TLPLabel]map[string]struct{}{},
			}

			if err := p.integrity(files, feedBase, rolieMask, p.badProviderMetadata.add); err != nil {
				if err != errContinue {
					return err
				}
			}
		}
	}

	// Phase 3: Check for completeness.

	hasSummary := map[csaf.TLPLabel]struct{}{}

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
			advisories := make(map[string]struct{}, len(reference))

			for _, adv := range files {
				u, err := url.Parse(adv.URL())
				if err != nil {
					p.badProviderMetadata.error("Invalid URL %s in feed: %v.", *feed.URL, err)
					continue
				}
				advisories[makeAbs(u).String()] = struct{}{}
			}
			if containsAllKeys(reference, advisories) {
				hasSummary[label] = struct{}{}
			}
		}
	}

	if !hasWhite && !hasGreen && !hasUnlabeled {
		p.badROLIEfeed.error(
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
		if _, ok := hasSummary[label]; !ok && len(p.labelChecker.advisories[label]) > 0 {
			p.badROLIEfeed.warn(
				"ROLIE feed for TLP:%s has no accessible listed feed covering all advisories.",
				label)
		}
	}

	return nil
}

// containsAllKeys returns if m2 contains all keys of m1.
func containsAllKeys[K comparable, V any](m1, m2 map[K]V) bool {
	for k := range m1 {
		if _, ok := m2[k]; !ok {
			return false
		}
	}
	return true
}
