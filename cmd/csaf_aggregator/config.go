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
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"sync"

	"github.com/BurntSushi/toml"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/csaf-poc/csaf_distribution/csaf"
	"github.com/csaf-poc/csaf_distribution/util"
	"golang.org/x/time/rate"
)

const (
	defaultConfigPath = "aggregator.toml"
	defaultWorkers    = 10
	defaultFolder     = "/var/www"
	defaultWeb        = "/var/www/html"
	defaultDomain     = "https://example.com"
)

type provider struct {
	Name   string `toml:"name"`
	Domain string `toml:"domain"`
	// Rate gives the provider specific rate limiting (see overall Rate).
	Rate     *float64 `toml:"rate"`
	Insecure *bool    `toml:"insecure"`
}

type config struct {
	Verbose bool `toml:"verbose"`
	// Workers is the number of concurrently executed workers for downloading.
	Workers int    `toml:"workers"`
	Folder  string `toml:"folder"`
	Web     string `toml:"web"`
	Domain  string `toml:"domain"`
	// Rate gives the average upper limit of https operations per second.
	Rate                *float64            `toml:"rate"`
	Insecure            *bool               `toml:"insecure"`
	Aggregator          csaf.AggregatorInfo `toml:"aggregator"`
	Providers           []*provider         `toml:"providers"`
	OpenPGPPrivateKey   string              `toml:"openpgp_private_key"`
	OpenPGPPublicKey    string              `toml:"openpgp_public_key"`
	Passphrase          *string             `toml:"passphrase"`
	AllowSingleProvider bool                `toml:"allow_single_provider"`

	// LockFile tries to lock to a given file.
	LockFile *string `toml:"lock_file"`

	// Interim performs an interim scan.
	Interim bool `toml:"interim"`

	// InterimYears is numbers numbers of years to look back
	// for interim advisories. Less/equal zero means forever.
	InterimYears int `toml:"interim_years"`

	// RemoteValidator configures an optional remote validation.
	RemoteValidatorOptions *csaf.RemoteValidatorOptions `toml:"remote_validator"`

	keyMu  sync.Mutex
	key    *crypto.Key
	keyErr error
}

// runAsMirror determines if the aggregator should run in mirror mode.
func (c *config) runAsMirror() bool {
	return c.Aggregator.Category != nil &&
		*c.Aggregator.Category == csaf.AggregatorAggregator
}

func (c *config) privateOpenPGPKey() (*crypto.Key, error) {
	if c.OpenPGPPrivateKey == "" {
		return nil, nil
	}
	c.keyMu.Lock()
	defer c.keyMu.Unlock()
	if c.key != nil || c.keyErr != nil {
		return c.key, c.keyErr
	}
	var f *os.File
	if f, c.keyErr = os.Open(c.OpenPGPPrivateKey); c.keyErr != nil {
		return nil, c.keyErr
	}
	defer f.Close()
	c.key, c.keyErr = crypto.NewKeyFromArmoredReader(f)
	return c.key, c.keyErr
}

func (c *config) httpClient(p *provider) util.Client {

	hClient := http.Client{}
	if p.Insecure != nil && *p.Insecure || c.Insecure != nil && *c.Insecure {
		hClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	}

	var client util.Client

	if c.Verbose {
		client = &util.LoggingClient{Client: &hClient}
	} else {
		client = &hClient
	}

	if p.Rate == nil && c.Rate == nil {
		return client
	}

	var r float64
	if c.Rate != nil {
		r = *c.Rate
	}
	if p.Rate != nil {
		r = *p.Rate
	}
	return &util.LimitingClient{
		Client:  client,
		Limiter: rate.NewLimiter(rate.Limit(r), 1),
	}
}

func (c *config) checkProviders() error {

	if !c.AllowSingleProvider && len(c.Providers) < 2 {
		return errors.New("need at least two providers")
	}

	already := make(map[string]bool)

	for _, p := range c.Providers {
		if p.Name == "" {
			return errors.New("no name given for provider")
		}
		if p.Domain == "" {
			return errors.New("no domain given for provider")
		}
		if already[p.Name] {
			return fmt.Errorf("provider '%s' is configured more than once", p.Name)
		}
		already[p.Name] = true
	}
	return nil
}

func (c *config) setDefaults() {
	if c.Folder == "" {
		c.Folder = defaultFolder
	}

	if c.Web == "" {
		c.Web = defaultWeb
	}

	if c.Domain == "" {
		c.Domain = defaultDomain
	}

	if c.Workers <= 0 {
		if n := runtime.NumCPU(); n > defaultWorkers {
			c.Workers = defaultWorkers
		} else {
			c.Workers = n
		}
	}

	if c.Workers > len(c.Providers) {
		c.Workers = len(c.Providers)
	}
}

func (c *config) check() error {
	if len(c.Providers) == 0 {
		return errors.New("no providers given in configuration")
	}

	if err := c.Aggregator.Validate(); err != nil {
		return err
	}

	return c.checkProviders()
}

func loadConfig(path string) (*config, error) {
	if path == "" {
		path = defaultConfigPath
	}

	var cfg config
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, err
	}

	cfg.setDefaults()

	if err := cfg.check(); err != nil {
		return nil, err
	}

	return &cfg, nil
}
