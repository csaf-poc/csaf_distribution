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
	"log/slog"
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
	"golang.org/x/time/rate"

	"github.com/csaf-poc/csaf_distribution/v2/csaf"
	"github.com/csaf-poc/csaf_distribution/v2/util"
)

type downloader struct {
	cfg       *config
	directory string
	keys      *crypto.KeyRing
	eval      *util.PathEval
	validator csaf.RemoteValidator
	forwarder *forwarder
	mkdirMu   sync.Mutex
}

func newDownloader(cfg *config) (*downloader, error) {

	var validator csaf.RemoteValidator

	if cfg.RemoteValidator != "" {
		validatorOptions := csaf.RemoteValidatorOptions{
			URL:     cfg.RemoteValidator,
			Presets: cfg.RemoteValidatorPresets,
			Cache:   cfg.RemoteValidatorCache,
		}
		var err error
		if validator, err = validatorOptions.Open(); err != nil {
			return nil, fmt.Errorf(
				"preparing remote validator failed: %w", err)
		}
		validator = csaf.SynchronizedRemoteValidator(validator)
	}

	return &downloader{
		cfg:       cfg,
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
	if d.cfg.Insecure {
		tlsConfig.InsecureSkipVerify = true
	}

	if len(d.cfg.clientCerts) != 0 {
		tlsConfig.Certificates = d.cfg.clientCerts
	}

	hClient.Transport = &http.Transport{
		TLSClientConfig: &tlsConfig,
	}

	client := util.Client(&hClient)

	// Add extra headers.
	if len(d.cfg.ExtraHeader) > 0 {
		client = &util.HeaderClient{
			Client: client,
			Header: d.cfg.ExtraHeader,
		}
	}

	// Add optional URL logging.
	if d.cfg.Verbose {
		client = &util.LoggingClient{Client: client}
	}

	// Add optional rate limiting.
	if d.cfg.Rate != nil {
		client = &util.LimitingClient{
			Client:  client,
			Limiter: rate.NewLimiter(rate.Limit(*d.cfg.Rate), 1),
		}
	}

	return client
}

func (d *downloader) download(ctx context.Context, domain string) error {
	client := d.httpClient()

	loader := csaf.NewProviderMetadataLoader(client)

	lpmd := loader.Load(domain)

	if d.cfg.Verbose {
		for i := range lpmd.Messages {
			slog.Info("Loading provider-metadata.json",
				"domain", domain,
				"message", lpmd.Messages[i].Message)
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
		base)

	// Do we need time range based filtering?
	if d.cfg.Range != nil {
		afp.AgeAccept = d.cfg.Range.Contains
	}

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
	if n = d.cfg.Worker; n < 1 {
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
			slog.Warn("Invalid URL",
				"url", *key.URL,
				"error", err)
			continue
		}

		u := base.ResolveReference(up).String()

		res, err := client.Get(u)
		if err != nil {
			slog.Warn(
				"Fetching public OpenPGP key failed",
				"url", u,
				"error", err)
			continue
		}
		if res.StatusCode != http.StatusOK {
			slog.Warn(
				"Fetching public OpenPGP key failed",
				"url", u,
				"status_code", res.StatusCode,
				"status", res.Status)
			continue
		}

		ckey, err := func() (*crypto.Key, error) {
			defer res.Body.Close()
			return crypto.NewKeyFromArmoredReader(res.Body)
		}()

		if err != nil {
			slog.Warn(
				"Reading public OpenPGP key failed",
				"url", u,
				"error", err)
			continue
		}

		if !strings.EqualFold(ckey.GetFingerprint(), string(key.Fingerprint)) {
			slog.Warn(
				"Fingerprint of public OpenPGP key does not match remotely loaded",
				"url", u)
			continue
		}
		if d.keys == nil {
			if keyring, err := crypto.NewKeyRing(ckey); err != nil {
				slog.Warn(
					"Creating store for public OpenPGP key failed",
					"url", u,
					"error", err)
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
		slog.Error("Failed to validate",
			"url", url,
			"error", err)
		return
	}
	if len(errors) > 0 {
		if d.cfg.Verbose {
			slog.Error("CSAF file has validation errors",
				"url", url,
				"error", strings.Join(errors, ", "))
		} else {
			slog.Error("CSAF file has validation errors",
				"url", url,
				"count", len(errors))
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
			slog.Warn("Ignoring invalid URL",
				"url", file.URL(),
				"error", err)
			continue
		}

		// Ignore not conforming filenames.
		filename := filepath.Base(u.Path)
		if !util.ConformingFileName(filename) {
			slog.Warn("Ignoring none conforming filename",
				"filename", filename)
			continue
		}

		if d.cfg.ignoreURL(file.URL()) {
			if d.cfg.Verbose {
				slog.Warn("Ignoring URL", "url", file.URL())
			}
			continue
		}

		resp, err := client.Get(file.URL())
		if err != nil {
			slog.Warn("Cannot GET",
				"url", file.URL(),
				"error", err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			slog.Warn("Cannot load",
				"url", file.URL(),
				"status", resp.Status,
				"status_code", resp.StatusCode)
			continue
		}

		// Warn if we do not get JSON.
		if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
			slog.Warn("Content type is not 'application/json'",
				"url", file.URL(),
				"content_type", ct)
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
			if d.cfg.Verbose {
				slog.Warn("Cannot fetch SHA256",
					"url", file.SHA256URL(),
					"error", err)
			}
		} else {
			s256 = sha256.New()
			writers = append(writers, s256)
		}

		if remoteSHA512, s512Data, err = loadHash(client, file.SHA512URL()); err != nil {
			if d.cfg.Verbose {
				slog.Warn("Cannot fetch SHA512",
					"url", file.SHA512URL(),
					"error", err)
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
			slog.Warn("Downloading failed",
				"url", file.URL(),
				"error", err)
			continue
		}

		// Compare the checksums.
		s256Check := func() error {
			if s256 != nil && !bytes.Equal(s256.Sum(nil), remoteSHA256) {
				return fmt.Errorf("SHA256 checksum of %s does not match", file.URL())
			}
			return nil
		}

		s512Check := func() error {
			if s512 != nil && !bytes.Equal(s512.Sum(nil), remoteSHA512) {
				return fmt.Errorf("SHA512 checksum of %s does not match", file.URL())
			}
			return nil
		}

		// Validate OpenPGG signature.
		keysCheck := func() error {
			// Only check signature if we have loaded keys.
			if d.keys == nil {
				return nil
			}
			var sign *crypto.PGPSignature
			sign, signData, err = loadSignature(client, file.SignURL())
			if err != nil {
				if d.cfg.Verbose {
					slog.Warn("Downloading signature failed",
						"url", file.SignURL(),
						"error", err)
				}
			}
			if sign != nil {
				if err := d.checkSignature(data.Bytes(), sign); err != nil {
					if !d.cfg.IgnoreSignatureCheck {
						return fmt.Errorf("cannot verify signature for %s: %v", file.URL(), err)
					}
				}
			}
			return nil
		}

		// Validate against CSAF schema.
		schemaCheck := func() error {
			if errors, err := csaf.ValidateCSAF(doc); err != nil || len(errors) > 0 {
				d.logValidationIssues(file.URL(), errors, err)
				return fmt.Errorf("schema validation for %q failed", file.URL())
			}
			return nil
		}

		// Validate if filename is conforming.
		filenameCheck := func() error {
			if err := util.IDMatchesFilename(d.eval, doc, filename); err != nil {
				return fmt.Errorf("filename not conforming %s: %s", file.URL(), err)
			}
			return nil
		}

		// Validate against remote validator.
		remoteValidatorCheck := func() error {
			if d.validator == nil {
				return nil
			}
			rvr, err := d.validator.Validate(doc)
			if err != nil {
				errorCh <- fmt.Errorf(
					"calling remote validator on %q failed: %w",
					file.URL(), err)
				return nil
			}
			if !rvr.Valid {
				return fmt.Errorf("remote validation of %q failed", file.URL())
			}
			return nil
		}

		// Run all the validations.
		valStatus := notValidatedValidationStatus
		for _, check := range []func() error{
			s256Check,
			s512Check,
			keysCheck,
			schemaCheck,
			filenameCheck,
			remoteValidatorCheck,
		} {
			if err := check(); err != nil {
				slog.Error("Validation check failed", "error", err)
				valStatus.update(invalidValidationStatus)
				if d.cfg.ValidationMode == validationStrict {
					continue nextAdvisory
				}
			}
		}
		valStatus.update(validValidationStatus)

		// Send to forwarder
		if d.forwarder != nil {
			d.forwarder.forward(
				filename, data.String(),
				valStatus,
				string(s256Data),
				string(s512Data))
		}

		if d.cfg.NoStore {
			// Do not write locally.
			continue
		}

		if err := d.eval.Extract(`$.document.tracking.initial_release_date`, dateExtract, false, doc); err != nil {
			slog.Warn("Cannot extract initial_release_date from advisory",
				"url", file.URL())
			initialReleaseDate = time.Now()
		}
		initialReleaseDate = initialReleaseDate.UTC()

		// Write advisory to file
		newDir := path.Join(d.directory, lower)

		// Do we have a configured destination folder?
		if d.cfg.Folder != "" {
			newDir = path.Join(newDir, d.cfg.Folder)
		} else {
			newDir = path.Join(newDir, strconv.Itoa(initialReleaseDate.Year()))
		}

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

		slog.Info("Written advisory", "path", path)
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
	if d.cfg.Directory == nil {
		dir, err := os.Getwd()
		if err != nil {
			return err
		}
		d.directory = dir
		return nil
	}
	// Use given directory
	if _, err := os.Stat(*d.cfg.Directory); err != nil {
		// If it does not exist create it.
		if os.IsNotExist(err) {
			if err = os.MkdirAll(*d.cfg.Directory, 0755); err != nil {
				return err
			}
		} else {
			return err
		}
	}
	d.directory = *d.cfg.Directory
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
