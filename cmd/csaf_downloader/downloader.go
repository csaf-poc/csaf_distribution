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
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/csaf-poc/csaf_distribution/csaf"
	"github.com/csaf-poc/csaf_distribution/util"
	"golang.org/x/time/rate"
)

type downloader struct {
	client    util.Client
	opts      *options
	directory string
	keys      []*crypto.KeyRing
	eval      *util.PathEval
}

func newDownloader(opts *options) *downloader {
	return &downloader{
		opts: opts,
		eval: util.NewPathEval(),
	}
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
		d.httpClient(), domain, func(format string, args ...any) {
			log.Printf(
				"Looking for provider-metadata.json of '"+domain+"': "+format+"\n", args...)
		})

	if !lpmd.Valid() {
		return fmt.Errorf("no valid provider-metadata.json found for '%s'", domain)
	}

	base, err := url.Parse(lpmd.URL)
	if err != nil {
		return fmt.Errorf("invalid URL '%s': %v", lpmd.URL, err)
	}

	if err := d.loadOpenPGPKeys(
		d.httpClient(),
		lpmd.Document,
		base,
	); err != nil {
		return err
	}

	afp := csaf.NewAdvisoryFileProcessor(
		d.httpClient(),
		d.eval,
		lpmd.Document,
		base,
		nil)

	return afp.Process(d.downloadFiles)
}

func (d *downloader) loadOpenPGPKeys(
	client util.Client,
	doc any,
	base *url.URL,
) error {

	src, err := d.eval.Eval("$.public_openpgp_keys", doc)
	if err != nil {
		// no keys.
		return nil
	}

	var keys []csaf.PGPKey
	if err := util.ReMarshalJSON(&keys, src); err != nil {
		return err
	}

	if len(keys) == 0 {
		return nil
	}

	// Try to load

	for i := range keys {
		key := &keys[i]
		if key.URL == nil {
			continue
		}
		up, err := url.Parse(*key.URL)
		if err != nil {
			log.Printf("Invalid URL '%s': %v", *key.URL, err)
			continue
		}

		u := base.ResolveReference(up).String()

		res, err := client.Get(u)
		if err != nil {
			log.Printf("Fetching public OpenPGP key %s failed: %v.", u, err)
			continue
		}
		if res.StatusCode != http.StatusOK {
			log.Printf("Fetching public OpenPGP key %s status code: %d (%s)",
				u, res.StatusCode, res.Status)
			continue
		}

		ckey, err := func() (*crypto.Key, error) {
			defer res.Body.Close()
			return crypto.NewKeyFromArmoredReader(res.Body)
		}()

		if err != nil {
			log.Printf("Reading public OpenPGP key %s failed: %v", u, err)
			continue
		}

		if !strings.EqualFold(ckey.GetFingerprint(), string(key.Fingerprint)) {
			log.Printf(
				"Fingerprint of public OpenPGP key %s does not match remotely loaded.", u)
			continue
		}
		keyring, err := crypto.NewKeyRing(ckey)
		if err != nil {
			log.Printf("Creating store for public OpenPGP key %s failed: %v.", u, err)
			continue
		}
		d.keys = append(d.keys, keyring)
	}
	return nil
}

// logValidationIssues logs the issues reported by the advisory schema validation.
func (d *downloader) logValidationIssues(url string, errors []string, err error) {
	if err != nil {
		log.Printf("Failed to validate %s: %v", url, err)
		return
	}
	if len(errors) > 0 {
		if d.opts.Verbose {
			log.Printf("CSAF file %s has validation errors: %s\n",
				url, strings.Join(errors, ", "))
		} else {
			log.Printf("CSAF file %s has %d validation errors.\n",
				url, len(errors))
		}
	}
}

func (d *downloader) downloadFiles(label csaf.TLPLabel, files []csaf.AdvisoryFile) error {

	client := d.httpClient()

	var data bytes.Buffer

	var lastDir string

	lower := strings.ToLower(string(label))

	var initialReleaseDate time.Time

	dateExtract := util.TimeMatcher(&initialReleaseDate, time.RFC3339)

	for _, file := range files {

		u, err := url.Parse(file.URL())
		if err != nil {
			log.Printf("Ignoring invalid URL: %s: %v\n", file.URL(), err)
			continue
		}

		// Ignore not confirming filenames.
		filename := filepath.Base(u.Path)
		if !util.ConfirmingFileName(filename) {
			log.Printf("Not confirming filename %q. Ignoring.\n", filename)
			continue
		}

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
			s256Data, s512Data         []byte
			remoteSHA256, remoteSHA512 []byte
			signData                   []byte
		)

		// Only hash when we have a remote counter part we can compare it with.
		if remoteSHA256, s256Data, err = d.loadHash(file.SHA256URL()); err != nil {
			if d.opts.Verbose {
				log.Printf("WARN: cannot fetch %s: %v\n", file.SHA256URL(), err)
			}
		} else {
			s256 = sha256.New()
			writers = append(writers, s256)
		}

		if remoteSHA512, s512Data, err = d.loadHash(file.SHA512URL()); err != nil {
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

		var doc any

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

		// Only check signature if we have loaded keys.
		if len(d.keys) > 0 {
			var sign *crypto.PGPSignature
			sign, signData, err = d.loadSignature(file.SignURL())
			if err != nil {
				if d.opts.Verbose {
					log.Printf("downloading signature '%s' failed: %v\n",
						file.SignURL(), err)
				}
			}
			if sign != nil {
				if !d.checkSignature(data.Bytes(), sign) {
					log.Printf("Cannot verify signature for %s\n", file.URL())
					continue
				}
			}
		}

		// Validate against CSAF schema.
		if errors, err := csaf.ValidateCSAF(doc); err != nil || len(errors) > 0 {
			d.logValidationIssues(file.URL(), errors, err)
			continue
		}

		if err := d.eval.Extract(`$.document.tracking.initial_release_date`, dateExtract, false, doc); err != nil {
			log.Printf("Cannot extract initial_release_date from advisory '%s'\n", file.URL())
			initialReleaseDate = time.Now()
		}
		initialReleaseDate = initialReleaseDate.UTC()

		// Write advisory to file

		newDir := path.Join(d.directory, lower, strconv.Itoa(initialReleaseDate.Year()))
		if newDir != lastDir {
			if err := os.MkdirAll(newDir, 0755); err != nil {
				return err
			}
			lastDir = newDir
		}

		path := filepath.Join(lastDir, filename)
		if err := os.WriteFile(path, data.Bytes(), 0644); err != nil {
			return err
		}

		// Write hash sums.
		if s256Data != nil {
			if err := os.WriteFile(path+".sha256", s256Data, 0644); err != nil {
				return err
			}
		}

		if s512Data != nil {
			if err := os.WriteFile(path+".sha512", s512Data, 0644); err != nil {
				return err
			}
		}

		// Write signature.
		if signData != nil {
			if err := os.WriteFile(path+".asc", signData, 0644); err != nil {
				return err
			}
		}

		log.Printf("Written advisory '%s'.\n", path)
	}

	return nil
}

func (d *downloader) checkSignature(data []byte, sign *crypto.PGPSignature) bool {
	pm := crypto.NewPlainMessage(data)
	t := crypto.GetUnixTime()
	for _, key := range d.keys {
		if err := key.VerifyDetached(pm, sign, t); err == nil {
			return true
		}
	}
	return false
}

func (d *downloader) loadSignature(p string) (*crypto.PGPSignature, []byte, error) {
	resp, err := d.httpClient().Get(p)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf(
			"fetching signature from '%s' failed: %s (%d)", p, resp.Status, resp.StatusCode)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	sign, err := crypto.NewPGPSignatureFromArmored(string(data))
	if err != nil {
		return nil, nil, err
	}
	return sign, data, nil
}

func (d *downloader) loadHash(p string) ([]byte, []byte, error) {
	resp, err := d.httpClient().Get(p)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf(
			"fetching hash from '%s' failed: %s (%d)", p, resp.Status, resp.StatusCode)
	}
	defer resp.Body.Close()
	var data bytes.Buffer
	tee := io.TeeReader(resp.Body, &data)
	hash, err := util.HashFromReader(tee)
	if err != nil {
		return nil, nil, err
	}
	return hash, data.Bytes(), nil
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
