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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/csaf-poc/csaf_distribution/v3/internal/options"
	"github.com/csaf-poc/csaf_distribution/v3/util"
)

func TestShaMarking(t *testing.T) {
	tests := []struct {
		name       string
		wantSha256 bool
		wantSha512 bool
	}{
		{
			name:       "want sha256 and sha512",
			wantSha256: true,
			wantSha512: true,
		},
	}

	t.Parallel()
	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			tt.Parallel()
			serverURL := ""
			fs := http.FileServer(http.Dir("../../testdata/simple-rolie-provider"))
			server := httptest.NewTLSServer(fs)
			defer server.Close()

			serverURL = server.URL

			hClient := server.Client()
			client := util.Client(hClient)

			cfg := config{LogLevel: &options.LogLevel{Level: slog.LevelDebug}}
			cfg.prepare()
			d, err := newDownloader(&cfg)
			if err != nil {
				t.Fatalf("could not init downloader: %v", err)
			}
			defer d.close()
			d.client = &client

			ctx := context.Background()
			err = d.run(ctx, []string{serverURL + "/provider-metadata.json"})
			if err != nil {
				t.Errorf("SHA marking: Expected no error, got: %v", err)
			}
		})
	}
}
