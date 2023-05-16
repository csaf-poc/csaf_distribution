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
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/json"
	"errors"
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
	"sync"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/csaf-poc/csaf_distribution/csaf"
	"github.com/csaf-poc/csaf_distribution/util"
	"golang.org/x/time/rate"
)

type downloader struct {
	opts      *options
	directory string
	keys      *crypto.KeyRing
	eval      *util.PathEval
	validator csaf.RemoteValidator
	mkdirMu   sync.Mutex
}

func newDownloader(opts *options) (*downloader, error) {

	var validator csaf.RemoteValidator

	if opts.RemoteValidator != "" {
		validatorOptions := csaf.RemoteValidatorOptions{
			URL:     opts.RemoteValidator,
			Presets: opts.RemoteValidatorPresets,
			Cache:   opts.RemoteValidatorCache,
		}
		var err error
		if validator, err = validatorOptions.Open(); err != nil {
			return nil, fmt.Errorf(
				"preparing remote validator failed: %w", err)
		}
		validator = csaf.SynchronizedRemoteValidator(validator)
	}

	return &downloader{
		opts:      opts,
		eval:      util.NewPathEval(),
		validator: validator,
	}, nil
}

func (d *downloader) close() {
	if d.validator != nil {
		d.validator.Close()
		d.validator = nil
	}
}

func (d *downloader) httpClient() util.Client {

	hClient := http.Client{}

	var tlsConfig tls.Config
	if d.opts.Insecure {
		tlsConfig.InsecureSkipVerify = true
		hClient.Transport = &http.Transport{
			TLSClientConfig: &tlsConfig,
		}
	}

	client := util.Client(&hClient)

	// Add extra headers.
	if len(d.opts.ExtraHeader) > 0 {
		client = &util.HeaderClient{
			Client: client,
			Header: d.opts.ExtraHeader,
		}
	}

	// Add optional URL logging.
	if d.opts.Verbose {
		client = &util.LoggingClient{Client: client}
	}

	// Add optional rate limiting.
	if d.opts.Rate != nil {
		client = &util.LimitingClient{
			Client:  client,
			Limiter: rate.NewLimiter(rate.Limit(*d.opts.Rate), 1),
		}
	}

	return client
}

func (d *downloader) download(ctx context.Context, domain string) error {
	client := d.httpClient()

	loader := csaf.NewProviderMetadataLoader(client)

	lpmd := loader.Load(domain)

	if d.opts.Verbose {
		for i := range lpmd.Messages {
			log.Printf("Loading provider-metadata.json for %q: %s\n",
				domain, lpmd.Messages[i].Message)
		}
	}

	if !lpmd.Valid() {
		return fmt.Errorf("no valid provider-metadata.json found for '%s'", domain)
	}

	base, err := url.Parse(lpmd.URL)
	if err != nil {
		return fmt.Errorf("invalid URL '%s': %v", lpmd.URL, err)
	}

	if err := d.loadOpenPGPKeys(
		client,
		lpmd.Document,
		base,
	); err != nil {
		return err
	}

	afp := csaf.NewAdvisoryFileProcessor(
		client,
		d.eval,
		lpmd.Document,
		base,
		nil)

	return afp.Process(func(label csaf.TLPLabel, files []csaf.AdvisoryFile) error {
		return d.downloadFiles(ctx, label, files)
	})
}

func (d *downloader) downloadFiles(
	ctx context.Context,
	label csaf.TLPLabel,
	files []csaf.AdvisoryFile,
) error {

	var (
		advisoryCh = make(chan csaf.AdvisoryFile)
		errorCh    = make(chan error)
		errDone    = make(chan struct{})
		errs       []error
		wg         sync.WaitGroup
	)

	// collect errors
	go func() {
		defer close(errDone)
		for err := range errorCh {
			errs = append(errs, err)
		}
	}()

	var n int
	if n = d.opts.Worker; n < 1 {
		n = 1
	}

	for i := 0; i < n; i++ {
		wg.Add(1)
		go d.downloadWorker(ctx, &wg, label, advisoryCh, errorCh)
	}

allFiles:
	for _, file := range files {
		select {
		case advisoryCh <- file:
		case <-ctx.Done():
			break allFiles
		}
	}

	close(advisoryCh)
	wg.Wait()
	close(errorCh)
	<-errDone

	return errors.Join(errs...)
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
		if d.keys == nil {
			if keyring, err := crypto.NewKeyRing(ckey); err != nil {
				log.Printf("Creating store for public OpenPGP key %s failed: %v.", u, err)
			} else {
				d.keys = keyring
			}
		} else {
			d.keys.AddKey(ckey)
		}
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

func (d *downloader) downloadWorker(
	ctx context.Context,
	wg *sync.WaitGroup,
	label csaf.TLPLabel,
	files <-chan csaf.AdvisoryFile,
	errorCh chan<- error,
) {
	defer wg.Done()

	var (
		client             = d.httpClient()
		data               bytes.Buffer
		lastDir            string
		initialReleaseDate time.Time
		dateExtract        = util.TimeMatcher(&initialReleaseDate, time.RFC3339)
		lower              = strings.ToLower(string(label))
	)

nextAdvisory:
	for {
		var file csaf.AdvisoryFile
		var ok bool
		select {
		case file, ok = <-files:
			if !ok {
				return
			}
		case <-ctx.Done():
			return
		}

		u, err := url.Parse(file.URL())
		if err != nil {
			log.Printf("Ignoring invalid URL: %s: %v\n", file.URL(), err)
			continue
		}

		// Ignore not conforming filenames.
		filename := filepath.Base(u.Path)
		if !util.ConformingFileName(filename) {
			log.Printf("Not conforming filename %q. Ignoring.\n", filename)
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

		// Warn if we do not get JSON.
		if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
			log.Printf(
				"WARN: The content type of %s should be 'application/json' but is '%s'\n",
				file.URL(), ct)
		}

		var (
			writers                    []io.Writer
			s256, s512                 hash.Hash
			s256Data, s512Data         []byte
			remoteSHA256, remoteSHA512 []byte
			signData                   []byte
		)

		// Only hash when we have a remote counter part we can compare it with.
		if remoteSHA256, s256Data, err = loadHash(client, file.SHA256URL()); err != nil {
			if d.opts.Verbose {
				log.Printf("WARN: cannot fetch %s: %v\n", file.SHA256URL(), err)
			}
		} else {
			s256 = sha256.New()
			writers = append(writers, s256)
		}

		if remoteSHA512, s512Data, err = loadHash(client, file.SHA512URL()); err != nil {
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
		if d.keys != nil {
			var sign *crypto.PGPSignature
			sign, signData, err = loadSignature(client, file.SignURL())
			if err != nil {
				if d.opts.Verbose {
					log.Printf("downloading signature '%s' failed: %v\n",
						file.SignURL(), err)
				}
			}
			if sign != nil {
				if err := d.checkSignature(data.Bytes(), sign); err != nil {
					log.Printf("Cannot verify signature for %s: %v\n", file.URL(), err)
					if !d.opts.IgnoreSignatureCheck {
						continue
					}
				}
			}
		}

		// Validate against CSAF schema.
		if errors, err := csaf.ValidateCSAF(doc); err != nil || len(errors) > 0 {
			d.logValidationIssues(file.URL(), errors, err)
			continue
		}

		if err := util.IDMatchesFilename(d.eval, doc, filename); err != nil {
			log.Printf("Ignoring %s: %s.\n", file.URL(), err)
			continue
		}

		// Validate against remote validator
		if d.validator != nil {
			rvr, err := d.validator.Validate(doc)
			if err != nil {
				errorCh <- fmt.Errorf(
					"calling remote validator on %q failed: %w",
					file.URL(), err)
				continue
			}
			if !rvr.Valid {
				log.Printf("Remote validation of %q failed\n", file.URL())
			}
		}

		if err := d.eval.Extract(`$.document.tracking.initial_release_date`, dateExtract, false, doc); err != nil {
			log.Printf("Cannot extract initial_release_date from advisory '%s'\n", file.URL())
			initialReleaseDate = time.Now()
		}
		initialReleaseDate = initialReleaseDate.UTC()

		// Write advisory to file

		newDir := path.Join(d.directory, lower, strconv.Itoa(initialReleaseDate.Year()))
		if newDir != lastDir {
			if err := d.mkdirAll(newDir, 0755); err != nil {
				errorCh <- err
				continue
			}
			lastDir = newDir
		}

		path := filepath.Join(lastDir, filename)

		// Write data to disk.
		for _, x := range []struct {
			p string
			d []byte
		}{
			{path, data.Bytes()},
			{path + ".sha256", s256Data},
			{path + ".sha512", s512Data},
			{path + ".asc", signData},
		} {
			if x.d != nil {
				if err := os.WriteFile(x.p, x.d, 0644); err != nil {
					errorCh <- err
					continue nextAdvisory
				}
			}
		}

		log.Printf("Written advisory '%s'.\n", path)
	}
}

func (d *downloader) mkdirAll(path string, perm os.FileMode) error {
	d.mkdirMu.Lock()
	defer d.mkdirMu.Unlock()
	return os.MkdirAll(path, perm)
}

func (d *downloader) checkSignature(data []byte, sign *crypto.PGPSignature) error {
	pm := crypto.NewPlainMessage(data)
	t := crypto.GetUnixTime()
	return d.keys.VerifyDetached(pm, sign, t)
}

func loadSignature(client util.Client, p string) (*crypto.PGPSignature, []byte, error) {
	resp, err := client.Get(p)
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

func loadHash(client util.Client, p string) ([]byte, []byte, error) {
	resp, err := client.Get(p)
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
func (d *downloader) run(ctx context.Context, domains []string) error {

	if err := d.prepareDirectory(); err != nil {
		return err
	}

	for _, domain := range domains {
		if err := d.download(ctx, domain); err != nil {
			return err
		}
	}
	return nil
}
