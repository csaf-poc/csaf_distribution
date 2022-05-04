// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package util

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/PaesslerAG/gval"
	"github.com/PaesslerAG/jsonpath"
)

// ReMarshalJSON transforms data from src to dst via JSON marshalling.
func ReMarshalJSON(dst, src interface{}) error {
	intermediate, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(intermediate, dst)
}

// PathEval is a helper to evaluate JSON paths on documents.
type PathEval struct {
	builder gval.Language
	exprs   map[string]gval.Evaluable
}

// NewPathEval creates a new PathEval.
func NewPathEval() *PathEval {
	return &PathEval{
		builder: gval.Full(jsonpath.Language()),
		exprs:   map[string]gval.Evaluable{},
	}
}

// Eval evalutes expression expr on document doc.
// Returns the result of the expression.
func (pe *PathEval) Eval(expr string, doc interface{}) (interface{}, error) {
	if doc == nil {
		return nil, errors.New("no document to extract data from")
	}
	eval := pe.exprs[expr]
	if eval == nil {
		var err error
		if eval, err = pe.builder.NewEvaluable(expr); err != nil {
			return nil, err
		}
		pe.exprs[expr] = eval
	}
	return eval(context.Background(), doc)
}

// PathEvalMatcher is a pair of an expression and an action
// when doing extractions via PathEval.Match.
type PathEvalMatcher struct {
	// Expr is the expression to evaluate
	Expr string
	// Action is executed with the result of the match.
	Action func(interface{}) error
}

// ReMarshalMatcher is an action to re-marshal the result to another type.
func ReMarshalMatcher(dst interface{}) func(interface{}) error {
	return func(src interface{}) error {
		return ReMarshalJSON(dst, src)
	}
}

// StringMatcher stores the matched result in a string.
func StringMatcher(dst *string) func(interface{}) error {
	return func(x interface{}) error {
		s, ok := x.(string)
		if !ok {
			return errors.New("not a string")
		}
		*dst = s
		return nil
	}
}

// TimeMatcher stores a time with a given format.
func TimeMatcher(dst *time.Time, format string) func(interface{}) error {
	return func(x interface{}) error {
		s, ok := x.(string)
		if !ok {
			return errors.New("not a string")
		}
		t, err := time.Parse(format, s)
		if err != nil {
			return nil
		}
		*dst = t
		return nil
	}
}

// Match matches a list of PathEvalMatcher pairs against a document.
func (pe *PathEval) Match(matcher []PathEvalMatcher, doc interface{}) error {
	for _, m := range matcher {
		x, err := pe.Eval(m.Expr, doc)
		if err != nil {
			return err
		}
		if err := m.Action(x); err != nil {
			return err
		}
	}
	return nil
}
