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
	"errors"
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
	URL          string
	EnableSha256 bool
	EnableSha512 bool
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
		case strings.HasSuffix(path, ".sha256") && directoryProvider && !params.EnableSha256:
			w.WriteHeader(http.StatusNotFound)
			return
		case strings.HasSuffix(path, ".sha512") && directoryProvider && !params.EnableSha512:
			w.WriteHeader(http.StatusNotFound)
			return
		default:
			w.Header().Add("Content-Type", "text/plain")
		}

		tmplt, err := template.New("base").Parse(string(content))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		err = tmplt.Execute(w, params)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	})
}

func checkIfFileExists(path string, t *testing.T) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	} else if errors.Is(err, os.ErrNotExist) {
		return false
	} else {
		t.Fatalf("Failed to check if file exists: %v", err)
		return false
	}
}

func TestShaMarking(t *testing.T) {
	tests := []struct {
		name              string
		directoryProvider bool
		wantSha256        bool
		wantSha512        bool
		enableSha256      bool
		enableSha512      bool
		preferredHash     hashAlgorithm
	}{
		{
			name:              "want sha256 and sha512",
			directoryProvider: false,
			wantSha256:        true,
			wantSha512:        true,
			enableSha256:      true,
			enableSha512:      true,
		},
		{
			name:              "only want sha256",
			directoryProvider: false,
			wantSha256:        true,
			wantSha512:        false,
			enableSha256:      true,
			enableSha512:      true,
			preferredHash:     algSha256,
		},
		{
			name:              "only want sha512",
			directoryProvider: false,
			wantSha256:        false,
			wantSha512:        true,
			enableSha256:      true,
			enableSha512:      true,
			preferredHash:     algSha512,
		},
		{
			name:              "only want sha512",
			directoryProvider: false,
			wantSha256:        false,
			wantSha512:        true,
			enableSha256:      true,
			enableSha512:      true,
			preferredHash:     algSha512,
		},

		{
			name:              "only deliver sha256",
			directoryProvider: false,
			wantSha256:        true,
			wantSha512:        false,
			enableSha256:      true,
			enableSha512:      false,
			preferredHash:     algSha512,
		},
		{
			name:              "only want sha256, directory provider",
			directoryProvider: true,
			wantSha256:        true,
			wantSha512:        false,
			enableSha256:      true,
			enableSha512:      true,
			preferredHash:     algSha256,
		},
		{
			name:              "only want sha512, directory provider",
			directoryProvider: true,
			wantSha256:        false,
			wantSha512:        true,
			enableSha256:      true,
			enableSha512:      true,
			preferredHash:     algSha512,
		},
	}

	t.Parallel()
	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			tt.Parallel()
			serverURL := ""
			params := ProviderParams{
				URL:          "",
				EnableSha256: test.enableSha256,
				EnableSha512: test.enableSha512,
			}
			server := httptest.NewTLSServer(ProviderHandler(&params, test.directoryProvider))
			defer server.Close()

			serverURL = server.URL
			params.URL = server.URL

			hClient := server.Client()
			client := util.Client(hClient)

			tempDir := t.TempDir()
			cfg := config{LogLevel: &options.LogLevel{Level: slog.LevelDebug}, Directory: tempDir, PreferredHash: test.preferredHash}
			err := cfg.prepare()
			if err != nil {
				t.Fatalf("SHA marking config failed: %v", err)
			}
			d, err := newDownloader(&cfg)
			if err != nil {
				t.Fatalf("could not init downloader: %v", err)
			}
			d.client = &client

			ctx := context.Background()
			err = d.run(ctx, []string{serverURL + "/provider-metadata.json"})
			if err != nil {
				t.Errorf("SHA marking %v: Expected no error, got: %v", test.name, err)
			}
			d.close()

			// Check for downloaded hashes
			sha256Exists := checkIfFileExists(tempDir+"/white/2020/avendor-advisory-0004.json.sha256", t)
			sha512Exists := checkIfFileExists(tempDir+"/white/2020/avendor-advisory-0004.json.sha512", t)

			if sha256Exists != test.wantSha256 {
				t.Errorf("%v: expected sha256 hash present to be %v, got: %v", test.name, test.wantSha256, sha256Exists)
			}

			if sha512Exists != test.wantSha512 {
				t.Errorf("%v: expected sha512 hash present to be %v, got: %v", test.name, test.wantSha512, sha512Exists)
			}
		})
	}
}
