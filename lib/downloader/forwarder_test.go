// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package downloader

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/csaf-poc/csaf_distribution/v3/util"
)

func TestValidationStatusUpdate(t *testing.T) {
	sv := ValidValidationStatus
	sv.update(InvalidValidationStatus)
	sv.update(ValidValidationStatus)
	if sv != InvalidValidationStatus {
		t.Fatalf("got %q expected %q", sv, InvalidValidationStatus)
	}
	sv = NotValidatedValidationStatus
	sv.update(ValidValidationStatus)
	sv.update(NotValidatedValidationStatus)
	if sv != NotValidatedValidationStatus {
		t.Fatalf("got %q expected %q", sv, NotValidatedValidationStatus)
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

	cfg := &Config{
		Logger: lg,
	}
	fw := NewForwarder(cfg)
	fw.failed = 11
	fw.succeeded = 13

	done := make(chan struct{})
	go func() {
		defer close(done)
		fw.Run()
	}()
	fw.Log()
	fw.Close()
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
	cfg := &Config{
		ForwardInsecure: true,
		ForwardHeader: http.Header{
			"User-Agent": []string{"curl/7.55.1"},
		},
		Logger: slog.Default(),
	}
	fw := NewForwarder(cfg)
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
	cfg := &Config{
		ForwardURL: "https://example.com",
	}
	fw := NewForwarder(cfg)

	req, err := fw.buildRequest(
		"test.json", "{}",
		InvalidValidationStatus,
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
			if vs := ValidationStatus(data); vs != InvalidValidationStatus {
				t.Fatalf("validation_status: got %q expected %q",
					vs, InvalidValidationStatus)
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
		InvalidValidationStatus,
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

type fakeClient struct {
	util.Client
	state int
}

func (fc *fakeClient) Do(*http.Request) (*http.Response, error) {
	// The different states simulates different responses from the remote API.
	switch fc.state {
	case 0:
		fc.state = 1
		return &http.Response{
			Status:     http.StatusText(http.StatusCreated),
			StatusCode: http.StatusCreated,
		}, nil
	case 1:
		fc.state = 2
		return nil, errors.New("does not work")
	case 2:
		fc.state = 3
		return &http.Response{
			Status:     http.StatusText(http.StatusBadRequest),
			StatusCode: http.StatusBadRequest,
			Body:       io.NopCloser(&badReader{error: os.ErrInvalid}),
		}, nil
	default:
		return &http.Response{
			Status:     http.StatusText(http.StatusBadRequest),
			StatusCode: http.StatusBadRequest,
			Body:       io.NopCloser(strings.NewReader("This was bad!")),
		}, nil
	}
}

func TestForwarderForward(t *testing.T) {
	dir, err := os.MkdirTemp("", "forward")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	orig := slog.Default()
	defer slog.SetDefault(orig)

	// We dont care in details here as we captured them
	// in the other test cases.
	h := slog.NewJSONHandler(io.Discard, nil)
	lg := slog.New(h)

	failedHandler := func(filename, doc, sha256, sha512 string) error {
		return nil
	}

	cfg := &Config{
		ForwardURL:           "http://example.com",
		Logger:               lg,
		FailedForwardHandler: failedHandler,
	}
	fw := NewForwarder(cfg)

	// Use the fact that http client is cached.
	fw.client = &fakeClient{}

	done := make(chan struct{})

	go func() {
		defer close(done)
		fw.Run()
	}()

	// Iterate through states of http client.
	for i := 0; i <= 3; i++ {
		fw.forward(
			"test.json", "{}",
			InvalidValidationStatus,
			"256",
			"512")
	}

	// Make buildRequest fail.
	wait := make(chan struct{})
	fw.cmds <- func(f *Forwarder) {
		f.cfg.ForwardURL = "%"
		close(wait)
	}
	<-wait
	fw.forward(
		"test.json", "{}",
		InvalidValidationStatus,
		"256",
		"512")

	fw.Close()

	<-done
}
