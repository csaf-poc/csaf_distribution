// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"testing"

	"github.com/csaf-poc/csaf_distribution/v3/internal/options"
)

func TestValidationStatusUpdate(t *testing.T) {
	sv := validValidationStatus
	sv.update(invalidValidationStatus)
	sv.update(validValidationStatus)
	if sv != invalidValidationStatus {
		t.Fatalf("got %q expected %q", sv, invalidValidationStatus)
	}
	sv = notValidatedValidationStatus
	sv.update(validValidationStatus)
	sv.update(notValidatedValidationStatus)
	if sv != notValidatedValidationStatus {
		t.Fatalf("got %q expected %q", sv, notValidatedValidationStatus)
	}
}

func TestForwarderLogStats(t *testing.T) {
	orig := slog.Default()
	defer slog.SetDefault(orig)

	var buf bytes.Buffer
	h := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	lg := slog.New(h)
	slog.SetDefault(lg)

	cfg := &config{}
	fw := newForwarder(cfg)
	fw.failed = 11
	fw.succeeded = 13

	done := make(chan struct{})
	go func() {
		defer close(done)
		fw.run()
	}()
	fw.log()
	fw.close()
	<-done

	type fwStats struct {
		Msg       string `json:"msg"`
		Succeeded int    `json:"succeeded"`
		Failed    int    `json:"failed"`
	}
	sc := bufio.NewScanner(bytes.NewReader(buf.Bytes()))
	found := false
	for sc.Scan() {
		var fws fwStats
		if err := json.Unmarshal(sc.Bytes(), &fws); err != nil {
			t.Fatalf("JSON parsing log failed: %v", err)
		}
		if fws.Msg == "Forward statistics" &&
			fws.Failed == 11 &&
			fws.Succeeded == 13 {
			found = true
			break
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scanning log failed: %v", err)
	}
	if !found {
		t.Fatal("Cannot find forward statistics in log")
	}
}

func TestForwarderHTTPClient(t *testing.T) {
	cfg := &config{
		ForwardInsecure: true,
		ForwardHeader: http.Header{
			"User-Agent": []string{"curl/7.55.1"},
		},
		LogLevel: &options.LogLevel{Level: slog.LevelDebug},
	}
	fw := newForwarder(cfg)
	if c1, c2 := fw.httpClient(), fw.httpClient(); c1 != c2 {
		t.Fatal("expected to return same client twice")
	}
}

func TestForwarderReplaceExtension(t *testing.T) {
	for _, x := range [][2]string{
		{"foo", "foo.ext"},
		{"foo.bar", "foo.ext"},
		{".bar", ".ext"},
		{"", ".ext"},
	} {
		if got := replaceExt(x[0], ".ext"); got != x[1] {
			t.Fatalf("got %q expected %q", got, x[1])
		}
	}
}
