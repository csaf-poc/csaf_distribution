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
	"log"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/csaf-poc/csaf_distribution/v2/internal/misc"
	"github.com/csaf-poc/csaf_distribution/v2/util"
)

type validationStatus string

const (
	validValidationStatus        = validationStatus("valid")
	invalidValidationStatus      = validationStatus("invalid")
	notValidatedValidationStatus = validationStatus("not_validated")
)

type forwarder struct {
	cfg    *config
	cmds   chan func(*forwarder)
	client util.Client
}

func newForwarder(cfg *config) *forwarder {
	queue := max(1, cfg.ForwardQueue)
	return &forwarder{
		cfg:  cfg,
		cmds: make(chan func(*forwarder), queue),
	}
}

func (f *forwarder) run() {
	defer log.Println("debug: forwarder done")

	for cmd := range f.cmds {
		cmd(f)
	}
}

func (f *forwarder) close() {
	close(f.cmds)
}

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

func replaceExt(fname, nExt string) string {
	ext := filepath.Ext(fname)
	return fname[:len(fname)-len(ext)] + nExt
}

func (f *forwarder) forward(
	filename, doc string,
	status validationStatus,
	sha256, sha512 string,
) {
	buildRequest := func() (*http.Request, error) {
		body := new(bytes.Buffer)
		writer := multipart.NewWriter(body)

		var err error
		send := func(name, fname, mimeType, content string) {
			if err != nil {
				return
			}
			var part io.Writer
			if fname == "" {
				err = writer.WriteField(name, content)
			} else if part, err = misc.CreateFormFile(writer, name, fname, mimeType); err == nil {
				_, err = part.Write([]byte(content))
			}
		}

		base := filepath.Base(filename)
		send("advisory", base, "application/json", doc)
		send("validation_status", "", "text/plain", string(status))
		if sha256 != "" {
			send("hash-256", replaceExt(base, ".sha256"), "text/plain", sha256)
		}
		if sha512 != "" {
			send("hash-512", replaceExt(base, ".sha512"), "text/plain", sha512)
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

	f.cmds <- func(f *forwarder) {
		req, err := buildRequest()
		if err != nil {
			// TODO: improve logging
			log.Printf("error: %v\n", err)
			return
		}
		res, err := f.httpClient().Do(req)
		if err != nil {
			// TODO: improve logging
			log.Printf("error: %v\n", err)
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
			log.Printf("error: %s: %q (%d)\n",
				filename, msg.String()+dots, res.StatusCode)
		} else {
			log.Printf("info: forwarding %q succeeded\n", filename)
		}
	}
}
