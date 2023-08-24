// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/csaf-poc/csaf_distribution/v2/internal/misc"
	"github.com/csaf-poc/csaf_distribution/v2/util"
)

// validationStatus represents the validation status
// known to the HTTP endpoint.
type validationStatus string

const (
	validValidationStatus        = validationStatus("valid")
	invalidValidationStatus      = validationStatus("invalid")
	notValidatedValidationStatus = validationStatus("not_validated")
)

func (vs *validationStatus) update(status validationStatus) {
	// Cannot heal after it fails at least once.
	if *vs != invalidValidationStatus {
		*vs = status
	}
}

// forwarder forwards downloaded advisories to a given
// HTTP endpoint.
type forwarder struct {
	cfg    *config
	cmds   chan func(*forwarder)
	client util.Client
}

// newForwarder creates a new forwarder.
func newForwarder(cfg *config) *forwarder {
	queue := max(1, cfg.ForwardQueue)
	return &forwarder{
		cfg:  cfg,
		cmds: make(chan func(*forwarder), queue),
	}
}

// run runs the forwarder. Meant to be used in a Go routine.
func (f *forwarder) run() {
	defer slog.Debug("forwarder done")

	for cmd := range f.cmds {
		cmd(f)
	}
}

// close terminates the forwarder.
func (f *forwarder) close() {
	close(f.cmds)
}

// httpClient returns a cached HTTP client used for uploading
// the advisories to the configured HTTP endpoint.
func (f *forwarder) httpClient() util.Client {
	if f.client != nil {
		return f.client
	}

	hClient := http.Client{}

	var tlsConfig tls.Config
	if f.cfg.ForwardInsecure {
		tlsConfig.InsecureSkipVerify = true
	}

	hClient.Transport = &http.Transport{
		TLSClientConfig: &tlsConfig,
	}

	client := util.Client(&hClient)

	// Add extra headers.
	if len(f.cfg.ForwardHeader) > 0 {
		client = &util.HeaderClient{
			Client: client,
			Header: f.cfg.ForwardHeader,
		}
	}

	// Add optional URL logging.
	if f.cfg.Verbose {
		client = &util.LoggingClient{Client: client}
	}

	f.client = client
	return f.client
}

// replaceExt replaces the extension of a given filename.
func replaceExt(fname, nExt string) string {
	ext := filepath.Ext(fname)
	return fname[:len(fname)-len(ext)] + nExt
}

// forward sends a given document with filename, status and
// checksums to the forwarder. This is async to the degree
// till the configured queue size is filled.
func (f *forwarder) forward(
	filename, doc string,
	status validationStatus,
	sha256, sha512 string,
) {
	buildRequest := func() (*http.Request, error) {
		body := new(bytes.Buffer)
		writer := multipart.NewWriter(body)

		var err error
		part := func(name, fname, mimeType, content string) {
			if err != nil {
				return
			}
			if fname == "" {
				err = writer.WriteField(name, content)
				return
			}
			var w io.Writer
			if w, err = misc.CreateFormFile(writer, name, fname, mimeType); err == nil {
				_, err = w.Write([]byte(content))
			}
		}

		base := filepath.Base(filename)
		part("advisory", base, "application/json", doc)
		part("validation_status", "", "text/plain", string(status))
		if sha256 != "" {
			part("hash-256", replaceExt(base, ".sha256"), "text/plain", sha256)
		}
		if sha512 != "" {
			part("hash-512", replaceExt(base, ".sha512"), "text/plain", sha512)
		}

		if err != nil {
			return nil, err
		}

		if err := writer.Close(); err != nil {
			return nil, err
		}

		req, err := http.NewRequest(http.MethodPost, f.cfg.ForwardURL, body)
		if err != nil {
			return nil, err
		}
		contentType := writer.FormDataContentType()
		req.Header.Set("Content-Type", contentType)
		return req, nil
	}

	// Run this in the main loop of the forwarder.
	f.cmds <- func(f *forwarder) {
		req, err := buildRequest()
		if err != nil {
			// TODO: improve logging
			slog.Error("building forward Request failed",
				"error", err)
			return
		}
		res, err := f.httpClient().Do(req)
		if err != nil {
			// TODO: improve logging
			slog.Error("sending forward request failed",
				"error", err)
			return
		}
		if res.StatusCode != http.StatusCreated {
			// TODO: improve logging
			defer res.Body.Close()
			var msg strings.Builder
			io.Copy(&msg, io.LimitReader(res.Body, 512))
			var dots string
			if msg.Len() >= 512 {
				dots = "..."
			}
			slog.Error("forwarding failed",
				"filename", filename,
				"body", msg.String()+dots,
				"status_code", res.StatusCode)

		} else {
			slog.Debug(
				"forwarding succeeded",
				"filename", filename)
		}
	}
}
