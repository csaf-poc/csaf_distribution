package main

import "github.com/csaf-poc/csaf_distribution/csaf"

type rolieCompletion struct {
	currentFeed  string
	currentLabel csaf.TLPLabel

	remain map[string]struct{}

	mismatch []matches
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

func (ca *rolieCompletion) reset() {
	ca.currentFeed = ""
	ca.currentLabel = ""
	ca.mismatch = nil
}

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

func (ca *rolieCompletion) checkCompletion(p *processor, tlpe csaf.TLPLabel, entryName string) {

	if ca.currentFeed == "" {
		// TODO: Do nothing?
		return
	}

	delete(ca.remain, entryName)

	// Assign int to tlp levels for easy comparison
	tlpen := tlpLevel(tlpe)

	tlpfn := tlpLevel(ca.currentLabel)

	// If entry shows up in feed of higher tlp level, save the combi to evaluate it when we know if feed
	// is summary feed or not
	switch {
	case tlpen < tlpfn:
		match := matches{
			feed:  ca.currentFeed,
			entry: entryName,
			tlpf:  ca.currentLabel,
			tlpe:  tlpe,
		}
		ca.mismatch = append(ca.mismatch, match)

	case tlpen > tlpfn:
		// Must not happen, give error
		p.badROLIEfeed.error(
			"%s of TLP level %s must not be listed in feed %s of TLP level %s",
			entryName, tlpe, ca.currentFeed, ca.currentLabel)
	}
}
