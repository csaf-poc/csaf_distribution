package main

import "github.com/csaf-poc/csaf_distribution/csaf"

type rolieCompletion struct {
	currentFeed      string
	currentFeedLevel csaf.TLPLabel

	unlabeled  tlpLevels
	wunlabeled tlpLevels
	white      tlpLevels
	green      tlpLevels
	amber      tlpLevels
	red        tlpLevels
	mismatch   []matches
}

// When going through all feeds, the summary feed is determined after going through all feeds.
// As such, save all mismatched non-error feeds here to easily determine whether to put this information
// into info or warning.
type matches struct {
	feed  string
	entry string
	tlpe  csaf.TLPLabel
	tlpf  csaf.TLPLabel
}

// tlpLevels holds all ROLIE feeds of a given tlp level that contain all entries of their given level
// as well as all entries of that level, meaning for a given tlpLevels all entries in feeds contain all entries
// in entries
type tlpLevels struct {
	feeds   []string
	entries []string
}

func (tlpls *tlpLevels) reset() {
	tlpls.feeds = nil
	tlpls.entries = nil
}

func (ca *rolieCompletion) reset() {
	ca.currentFeed = ""
	ca.currentFeedLevel = ""
	ca.unlabeled.reset()
	ca.wunlabeled.reset()
	ca.white.reset()
	ca.green.reset()
	ca.amber.reset()
	ca.red.reset()
	ca.mismatch = nil
}

func (ca *rolieCompletion) checkCompletion(p *processor, tlpe csaf.TLPLabel, entryName string) {

	if ca.currentFeed == "" {
		// TODO: Do nothing?
		return
	}

	// Assign int to tlp levels for easy comparison
	var tlpfn int
	var tlpen int
	switch tlpe {
	case "WHITE":
		tlpen = 1
		ca.white.addEntry(entryName)
	case "GREEN":
		tlpen = 2
		ca.green.addEntry(entryName)
	case "AMBER":
		tlpen = 3
		ca.amber.addEntry(entryName)
	case "RED":
		tlpen = 4
		ca.red.addEntry(entryName)
	default:
		tlpen = 0
		ca.unlabeled.addEntry(entryName)
	}
	switch ca.currentFeedLevel {
	case "WHITE":
		tlpfn = 1
	case "GREEN":
		tlpfn = 2
	case "AMBER":
		tlpfn = 3
	case "RED":
		tlpfn = 4
	default:
		tlpfn = 0
	}

	// If entry shows up in feed of higher tlp level, save the combi to evaluate it when we know if feed
	// is summary feed or not
	if tlpen < tlpfn {
		match := matches{
			feed:  ca.currentFeed,
			entry: entryName,
			tlpf:  ca.currentFeedLevel,
			tlpe:  tlpe,
		}
		ca.mismatch = append(ca.mismatch, match)
	}
	// Must not happen, give error
	if tlpen > tlpfn {
		p.badROLIEfeed.error(
			"%s of TLP level %s must not be listed in feed %s of TLP level %s",
			entryName, tlpe, ca.currentFeed, ca.currentFeedLevel)
	}
}

// checks if all entries of a given tlp level (thus far) appear in the current feeds list.
func (tlpls *tlpLevels) checkSummary(entrylist []csaf.AdvisoryFile) bool {
next:
	for _, e := range tlpls.entries {
		for _, s := range entrylist {
			if e == s.URL() {
				continue next
			}
		}
		return false
	}
	return true
}

func (ca *rolieCompletion) readySummary(entrylist []csaf.AdvisoryFile) {
	if ca.currentFeed == "" {
		return
	}
	switch ca.currentFeedLevel {
	case "WHITE":
		if ca.white.checkSummary(entrylist) {
			ca.white.feeds = append(ca.white.feeds, ca.currentFeed)
		}
		// wunlabeled holds all white feeds qualifying for summary feed of unlabeled if no unlabeled feed exists
		if ca.unlabeled.checkSummary(entrylist) {
			ca.wunlabeled.feeds = append(ca.wunlabeled.feeds, ca.currentFeed)
		}
	case "GREEN":
		if ca.green.checkSummary(entrylist) {
			ca.green.feeds = append(ca.green.feeds, ca.currentFeed)
		}
	case "AMBER":
		if ca.amber.checkSummary(entrylist) {
			ca.amber.feeds = append(ca.amber.feeds, ca.currentFeed)
		}
	case "RED":
		if ca.red.checkSummary(entrylist) {
			ca.red.feeds = append(ca.red.feeds, ca.currentFeed)
		}
	default:
		// if an unlabeled feed exists increment the entries of wunlabeled to mark it as unsuitable
		ca.wunlabeled.entries = append(ca.wunlabeled.entries, ca.currentFeed)
		if ca.unlabeled.checkSummary(entrylist) {
			ca.unlabeled.feeds = append(ca.unlabeled.feeds, ca.currentFeed)
		}
	}
}

func (ca *rolieCompletion) evaluate(p *processor) {
	if len(ca.red.entries) > 0 && len(ca.red.feeds) == 0 {
		p.badROLIEfeed.error("Missing ROLIE feed containing all entries with TLP:RED")
	}
	if len(ca.amber.entries) > 0 && len(ca.amber.feeds) == 0 {
		p.badROLIEfeed.error("Missing ROLIE feed containing all entries with TLP:AMBER")
	}
	if len(ca.green.entries) > 0 && len(ca.green.feeds) == 0 {
		p.badROLIEfeed.error("Missing ROLIE feed containing all entries with TLP:GREEN")
	}
	if len(ca.white.entries) > 0 && len(ca.white.feeds) == 0 {
		p.badROLIEfeed.error("Missing ROLIE feed containing all entries with TLP:WHITE")
	}
	if len(ca.unlabeled.entries) > 0 && len(ca.unlabeled.feeds) == 0 {
		if len(ca.wunlabeled.feeds) == 0 || len(ca.wunlabeled.entries) > 0 {
			p.badROLIEfeed.error("Missing ROLIE feed containing all entries without a TLP level")
		}
	}
	for _, mismatch := range ca.mismatch {
		var summary bool
		switch mismatch.tlpf {
		case "WHITE":
			for _, summaries := range ca.white.feeds {
				if summaries == mismatch.feed {
					summary = true
				}
			}
		case "GREEN":
			for _, summaries := range ca.green.feeds {
				if summaries == mismatch.feed {
					summary = true
				}
			}
		case "AMBER":
			for _, summaries := range ca.amber.feeds {
				if summaries == mismatch.feed {
					summary = true
				}
			}

		case "RED":
			for _, summaries := range ca.red.feeds {
				if summaries == mismatch.feed {
					summary = true
				}
			}
		}
		if summary {
			p.badROLIEfeed.warn("Advisory %s with TLP level %s appeared in ROLIE feed %s with TLP level %s", mismatch.entry, mismatch.tlpe, mismatch.feed, mismatch.tlpf)
		} else {
			p.badROLIEfeed.info("Advisory %s with TLP level %s appeared in ROLIE feed %s with TLP level %s", mismatch.entry, mismatch.tlpe, mismatch.feed, mismatch.tlpf)
		}
	}
}

// check if entry is already in tlpls
func (tlpls *tlpLevels) addEntry(entry string) {
	for _, en := range tlpls.entries {
		if entry == en {
			return
		}
	}
	tlpls.entries = append(tlpls.entries, entry)
	tlpls.feeds = nil
}
