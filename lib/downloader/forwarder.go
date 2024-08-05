// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package downloader

import (
	"bytes"
	"crypto/tls"
	"io"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/csaf-poc/csaf_distribution/v3/internal/misc"
	"github.com/csaf-poc/csaf_distribution/v3/util"
)

// failedForwardDir is the name of the special sub folder
// where advisories get stored which fail forwarding.
const failedForwardDir = "failed_forward"

// ValidationStatus represents the validation status
// known to the HTTP endpoint.
type ValidationStatus string

const (
	// ValidValidationStatus represents a valid document.
	ValidValidationStatus = ValidationStatus("valid")
	// InvalidValidationStatus represents an invalid document.
	InvalidValidationStatus = ValidationStatus("invalid")
	// NotValidatedValidationStatus represents a not validated document.
	NotValidatedValidationStatus = ValidationStatus("not_validated")
)

func (vs *ValidationStatus) update(status ValidationStatus) {
	// Cannot heal after it fails at least once.
	if *vs != InvalidValidationStatus {
		*vs = status
	}
}

// Forwarder forwards downloaded advisories to a given
// HTTP endpoint.
type Forwarder struct {
	cfg    *Config
	cmds   chan func(*Forwarder)
	client util.Client

	failed    int
	succeeded int
}

// NewForwarder creates a new Forwarder.
func NewForwarder(cfg *Config) *Forwarder {
	queue := cfg.ForwardQueue
	if queue < 1 {
		queue = 1
	}
	return &Forwarder{
		cfg:  cfg,
		cmds: make(chan func(*Forwarder), queue),
	}
}

// Run runs the Forwarder. Meant to be used in a Go routine.
func (f *Forwarder) Run() {
	defer f.cfg.Logger.Debug("Forwarder done")

	for cmd := range f.cmds {
		cmd(f)
	}
}

// Close terminates the Forwarder.
func (f *Forwarder) Close() {
	close(f.cmds)
}

// Log logs the current statistics.
func (f *Forwarder) Log() {
	f.cmds <- func(f *Forwarder) {
		f.cfg.Logger.Info("Forward statistics",
			"succeeded", f.succeeded,
			"failed", f.failed)
	}
}

// httpClient returns a cached HTTP client used for uploading
// the advisories to the configured HTTP endpoint.
func (f *Forwarder) httpClient() util.Client {
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
	if f.cfg.verbose() {
		client = &util.LoggingClient{
			Client: client,
			Log:    httpLog("Forwarder", f.cfg.Logger),
		}
	}

	f.client = client
	return f.client
}

// replaceExt replaces the extension of a given filename.
func replaceExt(fname, nExt string) string {
	ext := filepath.Ext(fname)
	return fname[:len(fname)-len(ext)] + nExt
}

// buildRequest creates an HTTP request suited to forward the given advisory.
func (f *Forwarder) buildRequest(
	filename, doc string,
	status ValidationStatus,
	sha256, sha512 string,
) (*http.Request, error) {
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

// storeFailed is a logging wrapper around storeFailedAdvisory.
func (f *Forwarder) storeFailed(filename, doc, sha256, sha512 string) {
	f.failed++
	if err := f.cfg.FailedForwardHandler(filename, doc, sha256, sha512); err != nil {
		f.cfg.Logger.Error("Storing advisory failed forwarding failed",
			"error", err)
	}
}

// limitedString reads max bytes from reader and returns it as a string.
// Longer strings are indicated by "..." as a suffix.
func limitedString(r io.Reader, max int) (string, error) {
	var msg strings.Builder
	if _, err := io.Copy(&msg, io.LimitReader(r, int64(max))); err != nil {
		return "", err
	}
	if msg.Len() >= max {
		msg.WriteString("...")
	}
	return msg.String(), nil
}

// forward sends a given document with filename, status and
// checksums to the Forwarder. This is async to the degree
// till the configured queue size is filled.
func (f *Forwarder) forward(
	filename, doc string,
	status ValidationStatus,
	sha256, sha512 string,
) {
	// Run this in the main loop of the Forwarder.
	f.cmds <- func(f *Forwarder) {
		req, err := f.buildRequest(filename, doc, status, sha256, sha512)
		if err != nil {
			f.cfg.Logger.Error("building forward Request failed",
				"error", err)
			f.storeFailed(filename, doc, sha256, sha512)
			return
		}
		res, err := f.httpClient().Do(req)
		if err != nil {
			f.cfg.Logger.Error("sending forward request failed",
				"error", err)
			f.storeFailed(filename, doc, sha256, sha512)
			return
		}
		if res.StatusCode != http.StatusCreated {
			defer res.Body.Close()
			if msg, err := limitedString(res.Body, 512); err != nil {
				f.cfg.Logger.Error("reading forward result failed",
					"error", err)
			} else {
				f.cfg.Logger.Error("forwarding failed",
					"filename", filename,
					"body", msg,
					"status_code", res.StatusCode)
			}
			f.storeFailed(filename, doc, sha256, sha512)
		} else {
			f.succeeded++
			f.cfg.Logger.Debug(
				"forwarding succeeded",
				"filename", filename)
		}
	}
}
