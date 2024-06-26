// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022, 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022, 2023 Intevation GmbH <https://intevation.de>

package downloader

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/csaf-poc/csaf_distribution/v3/internal/models"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"golang.org/x/time/rate"

	"github.com/csaf-poc/csaf_distribution/v3/csaf"
	"github.com/csaf-poc/csaf_distribution/v3/util"
)

// Downloader provides the CSAF downloader.
type Downloader struct {
	cfg       *Config
	keys      *crypto.KeyRing
	eval      *util.PathEval
	validator csaf.RemoteValidator
	Forwarder *Forwarder
	mkdirMu   sync.Mutex
	statsMu   sync.Mutex
	stats     stats
}

// DownloadedDocument contains the document data with additional metadata.
type DownloadedDocument struct {
	Data      []byte
	SHA256    []byte
	SHA512    []byte
	SignData  []byte
	Filename  string
	ValStatus ValidationStatus
}

// NewDownloader constructs a new downloader given the configuration.
func NewDownloader(cfg *Config) (*Downloader, error) {
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

	return &Downloader{
		cfg:       cfg,
		validator: validator,
	}, nil
}

// Close closes the downloader.
func (d *Downloader) Close() {
	if d.validator != nil {
		d.validator.Close()
		d.validator = nil
	}
}

// addStats add stats to total stats
func (d *Downloader) addStats(o *stats) {
	d.statsMu.Lock()
	defer d.statsMu.Unlock()
	d.stats.add(o)
}

// logRedirect logs redirects of the http client.
func logRedirect(logger *slog.Logger) func(req *http.Request, via []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		vs := make([]string, len(via))
		for i, v := range via {
			vs[i] = v.URL.String()
		}
		logger.Debug("Redirecting",
			"to", req.URL.String(),
			"via", strings.Join(vs, " -> "))
		return nil
	}
}

func (d *Downloader) httpClient() util.Client {
	hClient := http.Client{}

	if d.cfg.verbose() {
		hClient.CheckRedirect = logRedirect(d.cfg.Logger)
	}

	var tlsConfig tls.Config
	if d.cfg.Insecure {
		tlsConfig.InsecureSkipVerify = true
	}

	if len(d.cfg.ClientCerts) != 0 {
		tlsConfig.Certificates = d.cfg.ClientCerts
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
	if d.cfg.verbose() {
		client = &util.LoggingClient{
			Client: client,
			Log:    httpLog("downloader", d.cfg.Logger),
		}
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

// httpLog does structured logging in a [util.LoggingClient].
func httpLog(who string, logger *slog.Logger) func(string, string) {
	return func(method, url string) {
		logger.Debug("http",
			"who", who,
			"method", method,
			"url", url)
	}
}

func (d *Downloader) enumerate(domain string) error {
	client := d.httpClient()

	loader := csaf.NewProviderMetadataLoader(client)
	lpmd := loader.Enumerate(domain)

	var docs []any

	for _, pmd := range lpmd {
		if d.cfg.verbose() {
			for i := range pmd.Messages {
				d.cfg.Logger.Debug("Enumerating provider-metadata.json",
					"domain", domain,
					"message", pmd.Messages[i].Message)
			}
		}

		docs = append(docs, pmd.Document)
	}

	// print the results
	doc, err := json.MarshalIndent(docs, "", "  ")
	if err != nil {
		d.cfg.Logger.Error("Couldn't marshal PMD document json")
	}
	fmt.Println(string(doc))

	return nil
}

func (d *Downloader) download(ctx context.Context, domain string) error {
	client := d.httpClient()

	loader := csaf.NewProviderMetadataLoader(client)

	lpmd := loader.Load(domain)

	if !lpmd.Valid() {
		for i := range lpmd.Messages {
			slog.Error("Loading provider-metadata.json",
				"domain", domain,
				"message", lpmd.Messages[i].Message)
		}
		return fmt.Errorf("no valid provider-metadata.json found for '%s'", domain)
	} else if d.cfg.verbose() {
		for i := range lpmd.Messages {
			d.cfg.Logger.Debug("Loading provider-metadata.json",
				"domain", domain,
				"message", lpmd.Messages[i].Message)
		}
	}

	base, err := url.Parse(lpmd.URL)
	if err != nil {
		return fmt.Errorf("invalid URL '%s': %v", lpmd.URL, err)
	}

	expr := util.NewPathEval()

	if err := d.loadOpenPGPKeys(
		client,
		lpmd.Document,
		base,
		expr,
	); err != nil {
		return err
	}

	afp := csaf.NewAdvisoryFileProcessor(
		client,
		expr,
		lpmd.Document,
		base)

	// Do we need time range based filtering?
	if d.cfg.Range != nil {
		timeRange := models.NewTimeInterval(d.cfg.Range[0], d.cfg.Range[1])
		d.cfg.Logger.Debug("Setting up filter to accept advisories within",
			"timerange", timeRange)
		afp.AgeAccept = timeRange.Contains
	}

	return afp.Process(func(label csaf.TLPLabel, files []csaf.AdvisoryFile) error {
		return d.downloadFiles(ctx, files)
	})
}

func (d *Downloader) downloadFiles(
	ctx context.Context,
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
		go d.downloadWorker(ctx, &wg, advisoryCh, errorCh)
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

func (d *Downloader) loadOpenPGPKeys(
	client util.Client,
	doc any,
	base *url.URL,
	expr *util.PathEval,
) error {
	src, err := expr.Eval("$.public_openpgp_keys", doc)
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
			d.cfg.Logger.Warn("Invalid URL",
				"url", *key.URL,
				"error", err)
			continue
		}

		u := base.ResolveReference(up).String()

		res, err := client.Get(u)
		if err != nil {
			d.cfg.Logger.Warn(
				"Fetching public OpenPGP key failed",
				"url", u,
				"error", err)
			continue
		}
		if res.StatusCode != http.StatusOK {
			d.cfg.Logger.Warn(
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
			d.cfg.Logger.Warn(
				"Reading public OpenPGP key failed",
				"url", u,
				"error", err)
			continue
		}

		if !strings.EqualFold(ckey.GetFingerprint(), string(key.Fingerprint)) {
			d.cfg.Logger.Warn(
				"Fingerprint of public OpenPGP key does not match remotely loaded",
				"url", u)
			continue
		}
		if d.keys == nil {
			if keyring, err := crypto.NewKeyRing(ckey); err != nil {
				d.cfg.Logger.Warn(
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
func (d *Downloader) logValidationIssues(url string, errors []string, err error) {
	if err != nil {
		d.cfg.Logger.Error("Failed to validate",
			"url", url,
			"error", err)
		return
	}
	if len(errors) > 0 {
		if d.cfg.verbose() {
			d.cfg.Logger.Error("CSAF file has validation errors",
				"url", url,
				"error", strings.Join(errors, ", "))
		} else {
			d.cfg.Logger.Error("CSAF file has validation errors",
				"url", url,
				"count", len(errors))
		}
	}
}

func (d *Downloader) downloadWorker(
	ctx context.Context,
	wg *sync.WaitGroup,
	files <-chan csaf.AdvisoryFile,
	errorCh chan<- error,
) {
	defer wg.Done()

	var (
		client = d.httpClient()
		data   bytes.Buffer
		stats  = stats{}
		expr   = util.NewPathEval()
	)

	// Add collected stats back to total.
	defer d.addStats(&stats)

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
			stats.downloadFailed++
			d.cfg.Logger.Warn("Ignoring invalid URL",
				"url", file.URL(),
				"error", err)
			continue
		}

		if d.cfg.ignoreURL(file.URL()) {
			d.cfg.Logger.Debug("Ignoring URL", "url", file.URL())
			continue
		}

		// Ignore not conforming filenames.
		filename := filepath.Base(u.Path)
		if !util.ConformingFileName(filename) {
			stats.filenameFailed++
			d.cfg.Logger.Warn("Ignoring none conforming filename",
				"filename", filename)
			continue
		}

		resp, err := client.Get(file.URL())
		if err != nil {
			stats.downloadFailed++
			d.cfg.Logger.Warn("Cannot GET",
				"url", file.URL(),
				"error", err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			stats.downloadFailed++
			d.cfg.Logger.Warn("Cannot load",
				"url", file.URL(),
				"status", resp.Status,
				"status_code", resp.StatusCode)
			continue
		}

		// Warn if we do not get JSON.
		if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
			d.cfg.Logger.Warn("Content type is not 'application/json'",
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
			d.cfg.Logger.Warn("Cannot fetch SHA256",
				"url", file.SHA256URL(),
				"error", err)
		} else {
			s256 = sha256.New()
			writers = append(writers, s256)
		}

		if remoteSHA512, s512Data, err = loadHash(client, file.SHA512URL()); err != nil {
			d.cfg.Logger.Warn("Cannot fetch SHA512",
				"url", file.SHA512URL(),
				"error", err)
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
			stats.downloadFailed++
			d.cfg.Logger.Warn("Downloading failed",
				"url", file.URL(),
				"error", err)
			continue
		}

		// Compare the checksums.
		s256Check := func() error {
			if s256 != nil && !bytes.Equal(s256.Sum(nil), remoteSHA256) {
				stats.sha256Failed++
				return fmt.Errorf("SHA256 checksum of %s does not match", file.URL())
			}
			return nil
		}

		s512Check := func() error {
			if s512 != nil && !bytes.Equal(s512.Sum(nil), remoteSHA512) {
				stats.sha512Failed++
				return fmt.Errorf("SHA512 checksum of %s does not match", file.URL())
			}
			return nil
		}

		// Validate OpenPGP signature.
		keysCheck := func() error {
			// Only check signature if we have loaded keys.
			if d.keys == nil {
				return nil
			}
			var sign *crypto.PGPSignature
			sign, signData, err = loadSignature(client, file.SignURL())
			if err != nil {
				d.cfg.Logger.Warn("Downloading signature failed",
					"url", file.SignURL(),
					"error", err)
			}
			if sign != nil {
				if err := d.checkSignature(data.Bytes(), sign); err != nil {
					if !d.cfg.IgnoreSignatureCheck {
						stats.signatureFailed++
						return fmt.Errorf("cannot verify signature for %s: %v", file.URL(), err)
					}
				}
			}
			return nil
		}

		// Validate against CSAF schema.
		schemaCheck := func() error {
			if errs, err := csaf.ValidateCSAF(doc); err != nil || len(errs) > 0 {
				stats.schemaFailed++
				d.logValidationIssues(file.URL(), errs, err)
				return fmt.Errorf("schema validation for %q failed", file.URL())
			}
			return nil
		}

		// Validate if filename is conforming.
		filenameCheck := func() error {
			if err := util.IDMatchesFilename(expr, doc, filename); err != nil {
				stats.filenameFailed++
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
				stats.remoteFailed++
				return fmt.Errorf("remote validation of %q failed", file.URL())
			}
			return nil
		}

		// Run all the validations.
		valStatus := NotValidatedValidationStatus
		for _, check := range []func() error{
			s256Check,
			s512Check,
			keysCheck,
			schemaCheck,
			filenameCheck,
			remoteValidatorCheck,
		} {
			if err := check(); err != nil {
				d.cfg.Logger.Error("Validation check failed", "error", err)
				valStatus.update(InvalidValidationStatus)
				if d.cfg.ValidationMode == ValidationStrict {
					continue nextAdvisory
				}
			}
		}
		valStatus.update(ValidValidationStatus)

		// Send to Forwarder
		if d.Forwarder != nil {
			d.Forwarder.forward(
				filename, data.String(),
				valStatus,
				string(s256Data),
				string(s512Data))
		}

		download := DownloadedDocument{
			Data:      data.Bytes(),
			SHA256:    s256Data,
			SHA512:    s512Data,
			SignData:  signData,
			Filename:  filename,
			ValStatus: valStatus,
		}

		err = d.cfg.DownloadHandler(download)
		if err != nil {
			errorCh <- err
		} else {
			stats.succeeded++
		}
	}
}

func (d *Downloader) checkSignature(data []byte, sign *crypto.PGPSignature) error {
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

// Run performs the downloads for all the given domains.
func (d *Downloader) Run(ctx context.Context, domains []string) error {
	defer d.stats.log()
	for _, domain := range domains {
		if err := d.download(ctx, domain); err != nil {
			return err
		}
	}
	return nil
}

// RunEnumerate performs the enumeration of PMDs for all the given domains.
func (d *Downloader) RunEnumerate(domains []string) error {
	defer d.stats.log()
	for _, domain := range domains {
		if err := d.enumerate(domain); err != nil {
			return err
		}
	}
	return nil
}
