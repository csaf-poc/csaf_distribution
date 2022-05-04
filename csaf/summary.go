// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package csaf

import (
	"time"

	"github.com/csaf-poc/csaf_distribution/util"
)

const (
	idExpr                 = `$.document.tracking.id`
	titleExpr              = `$.document.title`
	publisherExpr          = `$.document.publisher`
	initialReleaseDateExpr = `$.document.tracking.initial_release_date`
	currentReleaseDateExpr = `$.document.tracking.current_release_date`
	tlpLabelExpr           = `$.document.distribution.tlp.label`
	summaryExpr            = `$.document.notes[? @.category=="summary" || @.type=="summary"].text`
)

// AdvisorySummary is a summary of some essentials of an CSAF advisory.
type AdvisorySummary struct {
	ID                 string
	Title              string
	Publisher          *Publisher
	InitialReleaseDate time.Time
	CurrentReleaseDate time.Time
	Summary            string
	TLPLabel           string
}

// NewAdvisorySummary creates a summary from an advisory doc
// with the help of an expression evaluator expr.
func NewAdvisorySummary(
	pe *util.PathEval,
	doc interface{},
) (*AdvisorySummary, error) {

	e := &AdvisorySummary{
		Publisher: new(Publisher),
	}

	if err := pe.Match([]util.PathEvalMatcher{
		{idExpr, util.StringMatcher(&e.ID)},
		{titleExpr, util.StringMatcher(&e.Title)},
		{currentReleaseDateExpr, util.TimeMatcher(&e.CurrentReleaseDate, time.RFC3339)},
		{initialReleaseDateExpr, util.TimeMatcher(&e.InitialReleaseDate, time.RFC3339)},
		{summaryExpr, util.StringMatcher(&e.Summary)},
		{tlpLabelExpr, util.StringMatcher(&e.TLPLabel)},
		{publisherExpr, util.ReMarshalMatcher(e.Publisher)},
	}, doc); err != nil {
		return nil, err
	}

	return e, nil
}
