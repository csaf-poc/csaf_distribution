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
	"html/template"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/csaf-poc/csaf_distribution/v3/internal/options"
	"github.com/csaf-poc/csaf_distribution/v3/util"
)

type ProviderParams struct {
	url          string
	enableSha256 bool
	enableSha512 bool
}

func ProviderHandler(params *ProviderParams, directoryProvider bool) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := "../../testdata/"
		if directoryProvider {
			path += "simple-directory-provider"
		} else {
			path += "simple-rolie-provider"
		}

		path += r.URL.Path

		if strings.HasSuffix(r.URL.Path, "/") {
			path += "index.html"
		}

		content, err := os.ReadFile(path)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch {
		case strings.HasSuffix(path, ".html"):
			w.Header().Add("Content-Type", "text/html")
		case strings.HasSuffix(path, ".json"):
			w.Header().Add("Content-Type", "application/json")
		default:
			w.Header().Add("Content-Type", "text/plain")
		}

		tmplt, err := template.New("base").Parse(string(content))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		tmplt.Execute(w, params)
	})
}

func TestShaMarking(t *testing.T) {
	tests := []struct {
		name              string
		directoryProvider bool
		wantSha256        bool
		wantSha512        bool
	}{
		{
			name:              "want sha256 and sha512",
			directoryProvider: false,
			wantSha256:        true,
			wantSha512:        true,
		},
	}

	t.Parallel()
	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			tt.Parallel()
			serverURL := ""
			params := ProviderParams{
				url:          "",
				enableSha256: true,
				enableSha512: true,
			}
			server := httptest.NewTLSServer(ProviderHandler(&params, test.directoryProvider))
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
