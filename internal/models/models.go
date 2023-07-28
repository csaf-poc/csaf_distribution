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
	"fmt"
	"strings"
	"time"
)

// TimeRange is a time interval.
type TimeRange [2]time.Time

// NewTimeInterval creates a new time range.
// The time values will be sorted.
func NewTimeInterval(a, b time.Time) TimeRange {
	if b.Before(a) {
		a, b = b, a
	}
	return TimeRange{a, b}
}

// guessDate tries to guess an RFC 3339 date time from a given string.
func guessDate(s string) (time.Time, bool) {
	for _, layout := range []string{
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02T15:04:05",
		"2006-01-02T15:04",
		"2006-01-02T15",
		"2006-01-02",
		"2006-01",
		"2006",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// UnmarshalText implements [encoding/text.TextUnmarshaler].
func (tr *TimeRange) UnmarshalText(text []byte) error {
	return tr.UnmarshalFlag(string(text))
}

// UnmarshalFlag implements [go-flags/Unmarshaler].
func (tr *TimeRange) UnmarshalFlag(s string) error {
	s = strings.TrimSpace(s)

	// Handle relative case first.
	if duration, err := time.ParseDuration(s); err == nil {
		now := time.Now()
		*tr = NewTimeInterval(now.Add(-duration), now)
		return nil
	}

	a, b, found := strings.Cut(s, ",")
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)

	// Only start date?
	if !found {
		start, ok := guessDate(a)
		if !ok {
			return fmt.Errorf("%q is not a valid RFC date time", a)
		}
		*tr = NewTimeInterval(start, time.Now())
		return nil
	}
	// Real interval
	start, ok := guessDate(a)
	if !ok {
		return fmt.Errorf("%q is not a valid RFC date time", a)
	}
	end, ok := guessDate(b)
	if !ok {
		return fmt.Errorf("%q is not a valid RFC date time", b)
	}
	*tr = NewTimeInterval(start, end)
	return nil
}

// Contains return true if the given time is inside this time interval.
func (tr TimeRange) Contains(t time.Time) bool {
	return !(t.Before(tr[0]) || t.After(tr[1]))
}
