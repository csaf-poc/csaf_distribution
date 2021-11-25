package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/PaesslerAG/gval"
	"github.com/PaesslerAG/jsonpath"

	"github.com/csaf-poc/csaf_distribution/csaf"
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

type extraction struct {
	id                 string
	title              string
	publisher          *csaf.Publisher
	initialReleaseDate time.Time
	currentReleaseDate time.Time
	summary            string
	tlpLabel           string
}

type extractFunc func(string) (interface{}, error)

func newExtraction(content interface{}) (*extraction, error) {

	builder := gval.Full(jsonpath.Language())

	path := func(expr string) (interface{}, error) {
		eval, err := builder.NewEvaluable(expr)
		if err != nil {
			return nil, err
		}
		return eval(context.Background(), content)
	}

	e := new(extraction)

	for _, fn := range []func(extractFunc) error{
		extractText(idExpr, &e.id),
		extractText(titleExpr, &e.title),
		extractTime(currentReleaseDateExpr, &e.currentReleaseDate),
		extractTime(initialReleaseDateExpr, &e.initialReleaseDate),
		extractText(summaryExpr, &e.summary),
		extractText(tlpLabelExpr, &e.tlpLabel),
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
		date, err := time.Parse(dateFormat, text)
		if err == nil {
			*store = date.UTC()
		}
		return err
	}
}

func (e *extraction) extractPublisher(path extractFunc) error {
	p, err := path(publisherExpr)
	if err != nil {
		return err
	}

	// XXX: It's a bit cumbersome to serialize and deserialize
	// it into our own structure.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if err := enc.Encode(p); err != nil {
		return err
	}
	e.publisher = new(csaf.Publisher)
	if err := json.Unmarshal(buf.Bytes(), e.publisher); err != nil {
		return err
	}
	return e.publisher.Validate()
}
