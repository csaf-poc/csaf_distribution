// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package models

import (
	"testing"
	"time"
)

// TestNewTimeInterval tests the creation of time intervals via NewTimeInterval()
func TestNewTimeInterval(t *testing.T) {
	var (
		before          = time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)
		after           = time.Date(2010, time.November, 10, 23, 0, 0, 0, time.UTC)
		pseudoTimeRange = TimeRange{before, after}
	)
	if NewTimeInterval(after, before) != pseudoTimeRange {
		t.Errorf("Failure: Couldn't generate timerange.")
	}
}

// TestGuessDate tests whether a sample of strings are correctly parsed into Dates by guessDate()
func TestGuessDate(t *testing.T) {
	if _, guess := guessDate("2006-01-02T15:04:05"); !guess {
		t.Errorf("Failure: Could not guess valid Date from valid string")
	}
	if _, guess := guessDate("2006"); !guess {
		t.Errorf("Failure: Could not guess valid Date from valid string")
	}
	if _, guess := guessDate("2006-01-02"); !guess {
		t.Errorf("Failure: Could not guess valid Date from valid string")
	}

	if _, guess := guessDate(""); guess {
		t.Errorf("Failure: Guessed Date from invalid string")
	}
}

// TestUnmarshalText tests whether UnmarshalText() correctly unmarshals a sample of byteSlices
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

// TestMarshalJSON tests whether MarshalJSON() correctly marshals a sample TimeRange
func TestMarshalJSON(t *testing.T) {
	testTimeRange := NewTimeInterval(
		time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC),
		time.Date(2010, time.November, 10, 23, 0, 0, 0, time.UTC))
	if _, err := testTimeRange.MarshalJSON(); err != nil {
		t.Errorf("Failure: %v", err)
	}
}

// TestUnmarshalFlag tests whether UnmarshalFlag() correctly extracts time from a given timeRange string.
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

// TestContains tests whether Contains() correctly identifies a sample of points in time to be within
// a timerange or not.
func TestContains(t *testing.T) {
	testTimeRange := NewTimeInterval(
		time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC),
		time.Date(2010, time.November, 10, 23, 0, 0, 0, time.UTC))
	testPointInTime := time.Date(2010, time.March, 10, 23, 0, 0, 0, time.UTC)
	testPointAfterTime := time.Date(2022, time.March, 10, 23, 0, 0, 0, time.UTC)
	testPointBeforeTime := time.Date(2002, time.March, 10, 23, 0, 0, 0, time.UTC)
	if !testTimeRange.Contains(testPointInTime) {
		t.Errorf("Failure: Did not recognize point within timerange correctly.")
	}
	if testTimeRange.Contains(testPointAfterTime) {
		t.Errorf("Failure: Did not recognize that a point in time was after a timerange correctly.")
	}
	if testTimeRange.Contains(testPointBeforeTime) {
		t.Errorf("Failure: Did not recognize that a point in time was before a timerange correctly.")
	}
}
