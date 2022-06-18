// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
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

	// TODO: Implement me!
	return nil
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
