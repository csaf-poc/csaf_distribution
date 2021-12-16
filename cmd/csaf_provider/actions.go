// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/csaf-poc/csaf_distribution/csaf"
	"github.com/csaf-poc/csaf_distribution/util"
)

const dateFormat = time.RFC3339

func cleanFileName(s string) string {
	s = strings.ReplaceAll(s, `/`, ``)
	s = strings.ReplaceAll(s, `\`, ``)
	r := regexp.MustCompile(`\.{2,}`)
	s = r.ReplaceAllString(s, `.`)
	return s
}

func (c *controller) loadCSAF(r *http.Request) (string, []byte, error) {
	file, handler, err := r.FormFile("csaf")
	if err != nil {
		return "", nil, err
	}
	defer file.Close()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, c.cfg.uploadLimiter(file)); err != nil {
		return "", nil, err
	}
	return cleanFileName(handler.Filename), buf.Bytes(), nil
}

func (c *controller) handleSignature(
	r *http.Request,
	data []byte,
) (string, *crypto.Key, error) {

	// Either way ... we need the key.
	key, err := c.cfg.loadCryptoKey()
	if err != nil {
		return "", nil, err
	}

	// Was the signature given via request?
	if c.cfg.UploadSignature {
		sigText := r.FormValue("signature")
		if sigText == "" {
			return "", nil, errors.New("missing signature in request")
		}

		pgpSig, err := crypto.NewPGPSignatureFromArmored(sigText)
		if err != nil {
			return "", nil, err
		}

		// Use as public key
		signRing, err := crypto.NewKeyRing(key)
		if err != nil {
			return "", nil, err
		}

		if err := signRing.VerifyDetached(
			crypto.NewPlainMessage(data),
			pgpSig, crypto.GetUnixTime(),
		); err != nil {
			return "", nil, err
		}

		return sigText, key, nil
	}

	// Sign ourself

	if passwd := r.FormValue("passphrase"); !c.cfg.NoPassphrase && passwd != "" {
		if key, err = key.Unlock([]byte(passwd)); err != nil {
			return "", nil, err
		}
	}

	// Use as private key
	signRing, err := crypto.NewKeyRing(key)
	if err != nil {
		return "", nil, err
	}

	sig, err := signRing.SignDetached(crypto.NewPlainMessage(data))
	if err != nil {
		return "", nil, err
	}

	armored, err := sig.GetArmored()
	return armored, key, err
}

func (c *controller) tlpParam(r *http.Request) (tlp, error) {
	t := tlp(strings.ToLower(r.FormValue("tlp")))
	for _, x := range c.cfg.TLPs {
		if x == t {
			return t, nil
		}
	}
	return "", fmt.Errorf("unsupported TLP type '%s'", t)
}

func (c *controller) create(*http.Request) (interface{}, error) {
	if err := ensureFolders(c.cfg); err != nil {
		return nil, err
	}
	return &struct {
		Message string `json:"message"`
		Error   bool   `json:"-"`
	}{
		Message: "Everything is setup fine now.",
	}, nil
}

func (c *controller) upload(r *http.Request) (interface{}, error) {

	newCSAF, data, err := c.loadCSAF(r)
	if err != nil {
		return nil, err
	}

	var content interface{}
	if err := json.Unmarshal(data, &content); err != nil {
		return nil, err
	}

	// Validate againt JSON schema.
	if !c.cfg.NoValidation {
		validationErrors, err := csaf.ValidateCSAF(content)
		if err != nil {
			return nil, err
		}

		if len(validationErrors) > 0 {
			return nil, multiError(validationErrors)
		}
	}

	ex, err := newExtraction(content)
	if err != nil {
		return nil, err
	}

	t, err := c.tlpParam(r)
	if err != nil {
		return nil, err
	}

	// Extract real TLP from document.
	if t == tlpCSAF {
		if t = tlp(strings.ToLower(ex.tlpLabel)); !t.valid() || t == tlpCSAF {
			return nil, fmt.Errorf("not a valid TL: %s", ex.tlpLabel)
		}
	}

	armored, key, err := c.handleSignature(r, data)
	if err != nil {
		return nil, err
	}

	var warnings []string
	warn := func(msg string) { warnings = append(warnings, msg) }

	if err := doTransaction(
		c.cfg, t,
		func(folder string, pmd *csaf.ProviderMetadata) error {

			// Load the feed
			ts := string(t)
			feedName := "csaf-feed-tlp-" + ts + ".json"

			feed := filepath.Join(folder, feedName)
			var rolie *csaf.ROLIEFeed
			if err := func() error {
				f, err := os.Open(feed)
				if err != nil {
					if os.IsNotExist(err) {
						return nil
					}
					return err
				}
				defer f.Close()
				rolie, err = csaf.LoadROLIEFeed(f)
				return err
			}(); err != nil {
				return err
			}

			feedURL := csaf.JSONURL(
				c.cfg.Domain + "/.well-known/csaf/" + ts + "/" + feedName)

			tlpLabel := csaf.TLPLabel(strings.ToUpper(ts))

			// Create new if does not exists.
			if rolie == nil {
				rolie = &csaf.ROLIEFeed{
					ID:    "csaf-feed-tlp-" + ts,
					Title: "CSAF feed (TLP:" + string(tlpLabel) + ")",
					Link: []csaf.Link{{
						Rel:  "rel",
						HRef: string(feedURL),
					}},
				}
			}

			rolie.Updated = csaf.TimeStamp(time.Now())

			year := strconv.Itoa(ex.initialReleaseDate.Year())

			csafURL := c.cfg.Domain +
				"/.well-known/csaf/" + ts + "/" + year + "/" + newCSAF

			e := rolie.EntryByID(ex.id)
			if e == nil {
				e = &csaf.Entry{ID: ex.id}
				rolie.Entry = append(rolie.Entry, e)
			}

			e.Titel = ex.title
			e.Published = csaf.TimeStamp(ex.initialReleaseDate)
			e.Updated = csaf.TimeStamp(ex.currentReleaseDate)
			e.Link = []csaf.Link{{
				Rel:  "self",
				HRef: csafURL,
			}}
			e.Format = csaf.Format{
				Schema:  "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json",
				Version: "2.0",
			}
			e.Content = csaf.Content{
				Type: "application/json",
				Src:  csafURL,
			}
			if ex.summary != "" {
				e.Summary = &csaf.Summary{Content: ex.summary}
			} else {
				e.Summary = nil
			}

			// Sort by descending updated order.
			rolie.SortEntriesByUpdated()

			// Store the feed
			if err := util.WriteToFile(feed, rolie); err != nil {
				return err
			}

			// Create yearly subfolder

			subDir := filepath.Join(folder, year)

			// Create folder if it does not exists.
			if _, err := os.Stat(subDir); err != nil {
				if os.IsNotExist(err) {
					if err := os.Mkdir(subDir, 0755); err != nil {
						return err
					}
				} else {
					return err
				}
			}

			fname := filepath.Join(subDir, newCSAF)

			if err := writeHashedFile(fname, newCSAF, data, armored); err != nil {
				return err
			}

			if err := updateIndices(
				folder, filepath.Join(year, newCSAF),
				ex.currentReleaseDate,
			); err != nil {
				return err
			}

			// Take over publisher
			switch {
			case pmd.Publisher == nil:
				warn("Publisher in provider metadata is not initialized. Forgot to configure?")
				if c.cfg.DynamicProviderMetaData {
					warn("Taking publisher from CSAF")
					pmd.Publisher = ex.publisher
				}
			case !pmd.Publisher.Equals(ex.publisher):
				warn("Publishers in provider metadata and CSAF do not match.")
			}

			pmd.SetPGP(key.GetFingerprint(), c.cfg.GetOpenPGPURL(key))

			return nil
		},
	); err != nil {
		return nil, err
	}

	result := struct {
		Name        string   `json:"name"`
		ReleaseDate string   `json:"release_date"`
		Warnings    []string `json:"warnings,omitempty"`
		Error       error    `json:"-"`
	}{
		Name:        newCSAF,
		ReleaseDate: ex.currentReleaseDate.Format(dateFormat),
		Warnings:    warnings,
	}

	return &result, nil
}
