// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

// Package models contains helper models used in the tools internally.
package models

import (
	"testing"
	"time"
)

func TestNewTimeInterval(t *testing.T) {
	var before time.Time
	before = time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)
	var after time.Time
	after = time.Date(2010, time.November, 10, 23, 0, 0, 0, time.UTC)
	NewTimeInterval(after, before)
}

func TestGuessDate(t *testing.T) {
	if _, guess := guessDate("2006-01-02T15:04:05"); !guess {
		t.Errorf("Failure: Could not guess valid Date from valid string")
	}
	if _, guess := guessDate(""); guess {
		t.Errorf("Failure: Guessed Date from invalid string")
	}
}

func TestUnmarshalText(t *testing.T) {
	testTimeRange := NewTimeInterval(
		time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC),
		time.Date(2010, time.November, 10, 23, 0, 0, 0, time.UTC))
	byteSlice := []byte{'3', 'h'}
	var emptySlice []byte
	if testTimeRange.UnmarshalText(byteSlice) != nil {
		t.Errorf(testTimeRange.UnmarshalText(byteSlice).Error())
	}
	if testTimeRange.UnmarshalText(emptySlice) == nil {
		t.Errorf("Failure: UnmarshalText succeeded on invalid slice of bytes.")
	}
}

func TestMarshalJSON(t *testing.T) {
	testTimeRange := NewTimeInterval(
		time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC),
		time.Date(2010, time.November, 10, 23, 0, 0, 0, time.UTC))
	testTimeRange.MarshalJSON()
}

func TestUnmarshalFlag(t *testing.T) {
	testTimeRange := NewTimeInterval(
		time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC),
		time.Date(2010, time.November, 10, 23, 0, 0, 0, time.UTC))
	if err := testTimeRange.UnmarshalFlag("3h"); err != nil {
		t.Errorf(err.Error())
	}
	if err := testTimeRange.UnmarshalFlag("2006-01-02T15:04:05"); err != nil {
		t.Errorf(err.Error())
	}
	if err := testTimeRange.UnmarshalFlag("2006-01-02T15:04:05a"); err == nil {
		t.Errorf("Failure: Extracted time from invalid string")
	}
	if err := testTimeRange.UnmarshalFlag("2006-01-02T15:04:05a, 2007-01-02T15:04:05"); err == nil {
		t.Errorf("Failure: Extracted time from invalid string")
	}
	if err := testTimeRange.UnmarshalFlag("2006-01-02T15:04:05, 2007-01-02T15:04:05a"); err == nil {
		t.Errorf("Failure: Extracted time from invalid string")
	}
	if err := testTimeRange.UnmarshalFlag("2006-01-02T15:04:05, 2007-01-02T15:04:05"); err != nil {
		t.Errorf(err.Error())
	}
}

func TestContains(t *testing.T) {
	testTimeRange := NewTimeInterval(
		time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC),
		time.Date(2010, time.November, 10, 23, 0, 0, 0, time.UTC))
	testPointInTime := time.Date(2010, time.March, 10, 23, 0, 0, 0, time.UTC)
	testTimeRange.Contains(testPointInTime)
}
