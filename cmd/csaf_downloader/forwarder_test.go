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
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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

func TestForwarderBuildRequest(t *testing.T) {

	// Good case ...
	cfg := &config{
		ForwardURL: "https://example.com",
	}
	fw := newForwarder(cfg)

	req, err := fw.buildRequest(
		"test.json", "{}",
		invalidValidationStatus,
		"256",
		"512")

	if err != nil {
		t.Fatalf("buildRequest failed: %v", err)
	}
	mediaType, params, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("no Content-Type found")
	}
	if !strings.HasPrefix(mediaType, "multipart/") {
		t.Fatalf("media type is not multipart")
	}
	mr := multipart.NewReader(req.Body, params["boundary"])

	var foundAdvisory, foundValidationStatus, found256, found512 bool

	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("parsing multipart failed: %v", err)
		}
		data, err := io.ReadAll(p)
		if err != nil {
			t.Fatal(err)
		}
		cd := p.Header["Content-Disposition"]
		if len(cd) == 0 {
			continue
		}

		switch contains := func(name string) bool {
			return strings.Contains(cd[0], `name="`+name+`"`)
		}; {
		case contains("advisory"):
			if a := string(data); a != "{}" {
				t.Fatalf("advisory: got %q expected %q", a, "{}")
			}
			foundAdvisory = true
		case contains("validation_status"):
			if vs := validationStatus(data); vs != invalidValidationStatus {
				t.Fatalf("validation_status: got %q expected %q",
					vs, invalidValidationStatus)
			}
			foundValidationStatus = true
		case contains("hash-256"):
			if h := string(data); h != "256" {
				t.Fatalf("hash-256: got %q expected %q", h, "256")
			}
			found256 = true
		case contains("hash-512"):
			if h := string(data); h != "512" {
				t.Fatalf("hash-512: got %q expected %q", h, "512")
			}
			found512 = true
		}
	}

	switch {
	case !foundAdvisory:
		t.Fatal("advisory not found")
	case !foundValidationStatus:
		t.Fatal("validation_status not found")
	case !found256:
		t.Fatal("hash-256 not found")
	case !found512:
		t.Fatal("hash-512 not found")
	}

	// Bad case ...
	cfg.ForwardURL = "%"

	if _, err := fw.buildRequest(
		"test.json", "{}",
		invalidValidationStatus,
		"256",
		"512",
	); err == nil {
		t.Fatal("bad forward URL should result in an error")
	}
}

type badReader struct{ error }

func (br *badReader) Read([]byte) (int, error) { return 0, br.error }

func TestLimitedString(t *testing.T) {
	for _, x := range [][2]string{
		{"xx", "xx"},
		{"xxx", "xxx..."},
		{"xxxx", "xxx..."},
	} {
		got, err := limitedString(strings.NewReader(x[0]), 3)
		if err != nil {
			t.Fatal(err)
		}
		if got != x[1] {
			t.Fatalf("got %q expected %q", got, x[1])
		}
	}

	if _, err := limitedString(&badReader{error: os.ErrInvalid}, 3); err == nil {
		t.Fatal("expected to fail with an error")
	}
}

func TestStoreFailedAdvisory(t *testing.T) {
	dir, err := os.MkdirTemp("", "storeFailed")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	cfg := &config{Directory: dir}
	fw := newForwarder(cfg)

	badDir := filepath.Join(dir, failedForwardDir)
	if err := os.WriteFile(badDir, []byte("test"), 0664); err != nil {
		t.Fatal(err)
	}

	if err := fw.storeFailedAdvisory("advisory.json", "{}", "256", "512"); err == nil {
		t.Fatal("if the destination exists as a file an error should occur")
	}

	if err := os.Remove(badDir); err != nil {
		t.Fatal(err)
	}

	if err := fw.storeFailedAdvisory("advisory.json", "{}", "256", "512"); err != nil {
		t.Fatal(err)
	}

	sha256Path := filepath.Join(dir, failedForwardDir, "advisory.json.sha256")

	// Write protect advisory.
	if err := os.Chmod(sha256Path, 0); err != nil {
		t.Fatal(err)
	}

	if err := fw.storeFailedAdvisory("advisory.json", "{}", "256", "512"); err == nil {
		t.Fatal("expected to fail with an error")
	}

	if err := os.Chmod(sha256Path, 644); err != nil {
		t.Fatal(err)
	}
}
