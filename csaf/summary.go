// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package csaf

import (
	"errors"
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

type extractFunc func(string) (interface{}, error)

// NewAdvisorySummary creates a summary from an advisory doc
// with the help of an expression evaluator expr.
func NewAdvisorySummary(
	expr *util.PathEval,
	doc interface{},
) (*AdvisorySummary, error) {

	e := new(AdvisorySummary)

	path := func(s string) (interface{}, error) {
		return expr.Eval(s, doc)
	}

	for _, fn := range []func(extractFunc) error{
		extractText(idExpr, &e.ID),
		extractText(titleExpr, &e.Title),
		extractTime(currentReleaseDateExpr, &e.CurrentReleaseDate),
		extractTime(initialReleaseDateExpr, &e.InitialReleaseDate),
		extractText(summaryExpr, &e.Summary),
		extractText(tlpLabelExpr, &e.TLPLabel),
		e.extractPublisher,
	} {
		if err := fn(path); err != nil {
			return nil, err
		}
	}

	return e, nil
}

func extractText(expr string, store *string) func(extractFunc) error {

	return func(path extractFunc) error {
		s, err := path(expr)
		if text, ok := s.(string); ok && err == nil {
			*store = text
		}
		return nil
	}
}

func extractTime(expr string, store *time.Time) func(extractFunc) error {

	return func(path extractFunc) error {
		s, err := path(expr)
		if err != nil {
			return err
		}
		text, ok := s.(string)
		if !ok {
			return errors.New("not a string")
		}
		date, err := time.Parse(time.RFC3339, text)
		if err == nil {
			*store = date.UTC()
		}
		return err
	}
}

func (e *AdvisorySummary) extractPublisher(path extractFunc) error {
	p, err := path(publisherExpr)
	if err != nil {
		return err
	}

	// XXX: It's a bit cumbersome to serialize and deserialize
	// it into our own structure.
	publisher := new(Publisher)
	if err := util.ReMarshalJSON(publisher, p); err != nil {
		return err
	}
	if err := publisher.Validate(); err != nil {
		return err
	}
	e.Publisher = publisher
	return nil
}
