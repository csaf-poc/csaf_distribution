// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/csaf-poc/csaf_distribution/csaf"
	"github.com/csaf-poc/csaf_distribution/util"
	"golang.org/x/time/rate"
)

type downloader struct {
	client    util.Client
	opts      *options
	directory string
}

func (d *downloader) httpClient() util.Client {

	if d.client != nil {
		return d.client
	}

	hClient := http.Client{}

	var tlsConfig tls.Config
	if d.opts.Insecure {
		tlsConfig.InsecureSkipVerify = true
		hClient.Transport = &http.Transport{
			TLSClientConfig: &tlsConfig,
		}
	}

	var client util.Client

	if d.opts.Verbose {
		client = &util.LoggingClient{Client: &hClient}
	} else {
		client = &hClient
	}

	if d.opts.Rate == nil {
		d.client = client
		return client
	}

	d.client = &util.LimitingClient{
		Client:  client,
		Limiter: rate.NewLimiter(rate.Limit(*d.opts.Rate), 1),
	}

	return d.client
}

func (d *downloader) download(domain string) error {

	lpmd := csaf.LoadProviderMetadataForDomain(
		d.httpClient(), domain, func(format string, args ...interface{}) {
			log.Printf(
				"Looking for provider-metadata.json of '"+domain+"': "+format+"\n", args...)
		})

	if lpmd == nil {
		return fmt.Errorf("no provider-metadata.json found for '%s'", domain)
	}

	base, err := url.Parse(lpmd.URL)
	if err != nil {
		return fmt.Errorf("invalid URL '%s': %v", lpmd.URL, err)
	}

	afp := csaf.NewAdvisoryFileProcessor(
		d.httpClient(),
		util.NewPathEval(),
		lpmd.Document,
		base)

	return afp.Process(d.downloadFiles)
}

func (d *downloader) downloadFiles(label csaf.TLPLabel, files []csaf.AdvisoryFile) error {

	client := d.httpClient()

	var data bytes.Buffer

	for _, file := range files {

		resp, err := client.Get(file.URL())
		if err != nil {
			log.Printf("WARN: cannot get '%s': %v\n", file.URL(), err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			log.Printf("WARN: cannot load %s: %s (%d)\n",
				file.URL(), resp.Status, resp.StatusCode)
			continue
		}

		var (
			writers                    []io.Writer
			s256, s512                 hash.Hash
			remoteSHA256, remoteSHA512 []byte
		)

		// Only hash when we have a remote counter part we can compare it with.
		if remoteSHA256, err = loadHash(file.SHA256URL(), client); err != nil {
			if d.opts.Verbose {
				log.Printf("WARN: cannot fetch %s: %v\n", file.SHA256URL(), err)
			}
		} else {
			s256 = sha256.New()
			writers = append(writers, s256)
		}

		if remoteSHA512, err = loadHash(file.SHA512URL(), client); err != nil {
			if d.opts.Verbose {
				log.Printf("WARN: cannot fetch %s: %v\n", file.SHA512URL(), err)
			}
		} else {
			s512 = sha512.New()
			writers = append(writers, s512)
		}

		// Remember the data as we need to store it to file later.
		data.Reset()
		writers = append(writers, &data)

		// Download the advisory and hash it.
		hasher := io.MultiWriter(writers...)

		var doc interface{}

		if err := func() error {
			defer resp.Body.Close()
			tee := io.TeeReader(resp.Body, hasher)
			return json.NewDecoder(tee).Decode(&doc)
		}(); err != nil {
			log.Printf("Downloading %s failed: %v", file.URL(), err)
			continue
		}

		// Compare the checksums.
		if s256 != nil && !bytes.Equal(s256.Sum(nil), remoteSHA256) {
			log.Printf("SHA256 checksum of %s does not match.\n", file.URL())
			continue
		}

		if s512 != nil && !bytes.Equal(s512.Sum(nil), remoteSHA512) {
			log.Printf("SHA512 checksum of %s does not match.\n", file.URL())
			continue
		}

		// TODO: Check signature.

		// Validate against CSAF schema.
		errors, err := csaf.ValidateCSAF(doc)
		if err != nil {
			log.Printf("Failed to validate %s: %v", file.URL(), err)
			continue
		}
		if len(errors) > 0 {
			log.Printf("CSAF file %s has %d validation errors.", file.URL(), len(errors))
			continue
		}

		// TODO: copy data to file.
	}

	return nil
}

func loadHash(p string, client util.Client) ([]byte, error) {
	resp, err := client.Get(p)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"fetching hash from '%s' failed: %s (%d)", p, resp.Status, resp.StatusCode)
	}
	defer resp.Body.Close()
	return util.HashFromReader(resp.Body)
}

// prepareDirectory ensures that the working directory
// exists and is setup properly.
func (d *downloader) prepareDirectory() error {
	// If no special given use current working directory.
	if d.opts.Directory == nil {
		dir, err := os.Getwd()
		if err != nil {
			return err
		}
		d.directory = dir
		return nil
	}
	// Use given directory
	if _, err := os.Stat(*d.opts.Directory); err != nil {
		// If it does not exist create it.
		if os.IsNotExist(err) {
			if err = os.MkdirAll(*d.opts.Directory, 0755); err != nil {
				return err
			}
		} else {
			return err
		}
	}
	d.directory = *d.opts.Directory
	return nil
}

// run performs the downloads for all the given domains.
func (d *downloader) run(domains []string) error {

	if err := d.prepareDirectory(); err != nil {
		return err
	}

	for _, domain := range domains {
		if err := d.download(domain); err != nil {
			return err
		}
	}
	return nil
}
