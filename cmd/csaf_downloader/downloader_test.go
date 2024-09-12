// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package main

import (
	"context"
	"log/slog"
	"testing"

	"github.com/csaf-poc/csaf_distribution/v3/csaf"
	"github.com/csaf-poc/csaf_distribution/v3/internal/options"
)

func TestShaMarking(t *testing.T) {
	cfg := config{LogLevel: &options.LogLevel{Level: slog.LevelDebug}}
	cfg.prepare()
	d, err := newDownloader(&cfg)
	if err != nil {
		t.Fatalf("could not init downloader: %v", err)
	}
	defer d.close()
	ctx := context.Background()
	files := []csaf.AdvisoryFile{}

	d.downloadFiles(ctx, csaf.TLPLabelWhite, files)
}
