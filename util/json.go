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
