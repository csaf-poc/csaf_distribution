// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

// Package filter implements helps to filter advisories.
package filter

import (
	"testing"
)

// NewPatternMatcher compiles a new list of regular expression from
// a given list of strings.
func TestNewPatternMatcher(t *testing.T) {
	var regex []string
	if pm, err := NewPatternMatcher(regex); pm == nil || err != nil {
		t.Errorf("Failure: Did not compile valid regex pattern")
	}
	regex = append(regex, "++")
	if pm, err := NewPatternMatcher(regex); pm != nil || err == nil {
		t.Errorf("Failure: No error thrown at invalid compile pattern")
	}
}

// Matches returns true if the given string matches any of the expressions.
func TestMatches(t *testing.T) {
	regex := []string{"a"}
	pm, _ := NewPatternMatcher(regex)
	if !pm.Matches("a") {
		t.Errorf("Failure: Did not match two identical strings")
	}
	if pm.Matches("b") {
		t.Errorf("Failure: Matched two non-matching strings")
	}
}
