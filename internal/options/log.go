// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package options

import (
	"log/slog"
	"strings"
)

// LogLevel implements a helper type to be used in configurations.
type LogLevel struct{ slog.Level }

// MarshalFlag implements [flags.Marshaler].
func (ll LogLevel) MarshalFlag() (string, error) {
	t, err := ll.MarshalText()
	return strings.ToLower(string(t)), err
}

// UnmarshalFlag implements [flags.Unmarshaler].
func (ll *LogLevel) UnmarshalFlag(value string) error {
	var l slog.Level
	if err := l.UnmarshalText([]byte(value)); err != nil {
		return err
	}
	*ll = LogLevel{Level: l}
	return nil
}
