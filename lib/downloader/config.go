// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package downloader

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/csaf-poc/csaf_distribution/v3/internal/filter"
	"github.com/csaf-poc/csaf_distribution/v3/internal/models"
)

// ValidationMode specifies the strict the validation is.
type ValidationMode string

const (
	// ValidationStrict skips advisories with failed validation.
	ValidationStrict = ValidationMode("strict")
	// ValidationUnsafe allows advisories with failed validation.
	ValidationUnsafe = ValidationMode("unsafe")
)

// Config provides the download configuration.
type Config struct {
	Insecure             bool
	IgnoreSignatureCheck bool
	ClientCerts          []tls.Certificate
	ClientKey            *string
	ClientPassphrase     *string
	Rate                 *float64
	Worker               int
	Range                *models.TimeRange
	IgnorePattern        filter.PatternMatcher
	ExtraHeader          http.Header

	RemoteValidator string
	// CLI only?
	RemoteValidatorCache   string
	RemoteValidatorPresets []string

	ValidationMode ValidationMode

	ForwardURL      string
	ForwardHeader   http.Header
	ForwardQueue    int
	ForwardInsecure bool

	DownloadHandler      func(DownloadedDocument) error
	FailedForwardHandler func(filename, doc, sha256, sha512 string) error

	Logger *slog.Logger
}

// UnmarshalText implements [encoding.TextUnmarshaler].
func (vm *ValidationMode) UnmarshalText(text []byte) error {
	switch m := ValidationMode(text); m {
	case ValidationStrict, ValidationUnsafe:
		*vm = m
	default:
		return fmt.Errorf(`invalid value %q (expected "strict" or "unsafe)"`, m)
	}
	return nil
}

// UnmarshalFlag implements [flags.UnmarshalFlag].
func (vm *ValidationMode) UnmarshalFlag(value string) error {
	var v ValidationMode
	if err := v.UnmarshalText([]byte(value)); err != nil {
		return err
	}
	*vm = v
	return nil
}

// ignoreFile returns true if the given URL should not be downloaded.
func (cfg *Config) ignoreURL(u string) bool {
	return cfg.IgnorePattern.Matches(u)
}

// verbose is considered a log level equal or less debug.
func (cfg *Config) verbose() bool {
	return cfg.Logger.Enabled(nil, slog.LevelDebug)
}
