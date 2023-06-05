// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package main

import "github.com/csaf-poc/csaf_distribution/v2/csaf"

// rolieLabelChecker helps to check id advisories in ROLIE feeds
// are in there right TLP color.
type rolieLabelChecker struct {
	feedURL   string
	feedLabel csaf.TLPLabel

	remain map[string]struct{}
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

	// If entry shows up in feed of higher tlp level, save the combi
	// to evaluate it when we know if feed is summary feed or not
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
		delete(ca.remain, advisory)

	case advisoryRank > feedRank:
		// Must not happen, give error
		p.badROLIEfeed.error(
			"%s of TLP level %s must not be listed in feed %s of TLP level %s",
			advisory, advisoryLabel, ca.feedURL, ca.feedLabel)

	default:
		// If this is empty all adivisories of a color were found.
		delete(ca.remain, advisory)
	}
}
