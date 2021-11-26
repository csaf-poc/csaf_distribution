package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/crypto"

	"github.com/csaf-poc/csaf_distribution/csaf"
)

const dateFormat = time.RFC3339

//go:embed tmpl
var tmplFS embed.FS

type controller struct {
	cfg  *config
	tmpl *template.Template
}

func newController(cfg *config) (*controller, error) {

	c := controller{cfg: cfg}
	var err error

	if c.tmpl, err = template.ParseFS(tmplFS, "tmpl/*.html"); err != nil {
		return nil, err
	}

	return &c, nil
}

func (c *controller) bind(pim *pathInfoMux) {
	pim.handleFunc("/", c.index)
	pim.handleFunc("/upload", c.upload)
	pim.handleFunc("/create", c.create)
}

func (c *controller) render(rw http.ResponseWriter, tmpl string, arg interface{}) {
	rw.Header().Set("Content-type", "text/html; charset=utf-8")
	if err := c.tmpl.ExecuteTemplate(rw, tmpl, arg); err != nil {
		log.Printf("warn: %v\n", err)
	}
}

func (c *controller) failed(rw http.ResponseWriter, tmpl string, err error) {
	rw.Header().Set("Content-type", "text/html; charset=utf-8")
	result := map[string]interface{}{"Error": err}
	if err := c.tmpl.ExecuteTemplate(rw, tmpl, result); err != nil {
		log.Printf("warn: %v\n", err)
	}
}

func (c *controller) index(rw http.ResponseWriter, r *http.Request) {
	c.render(rw, "index.html", map[string]interface{}{
		"Config": c.cfg,
	})
}

func (c *controller) create(rw http.ResponseWriter, r *http.Request) {
	if err := ensureFolders(c.cfg); err != nil {
		c.failed(rw, "create.html", err)
		return
	}
	c.render(rw, "create.html", nil)
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

func cleanFileName(s string) string {
	s = strings.ReplaceAll(s, `/`, ``)
	s = strings.ReplaceAll(s, `\`, ``)
	r := regexp.MustCompile(`\.{2,}`)
	s = r.ReplaceAllString(s, `.`)
	return s
}

func loadCSAF(r *http.Request) (string, []byte, error) {
	file, handler, err := r.FormFile("csaf")
	if err != nil {
		return "", nil, err
	}
	defer file.Close()

	var buf bytes.Buffer
	lr := io.LimitReader(file, 10*1024*1024)
	if _, err := io.Copy(&buf, lr); err != nil {
		return "", nil, err
	}
	return cleanFileName(handler.Filename), buf.Bytes(), nil
}

func (c *controller) loadCryptoKey() (*crypto.Key, error) {
	f, err := os.Open(c.cfg.Key)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return crypto.NewKeyFromArmoredReader(f)
}

func (c *controller) handleSignature(r *http.Request, data []byte) (string, string, error) {

	// Either way ... we need the key.
	key, err := c.loadCryptoKey()
	if err != nil {
		return "", "", err
	}

	fingerprint := key.GetFingerprint()

	// Was the signature given via request?
	if c.cfg.UploadSignature {
		sigText := r.FormValue("signature")
		if sigText == "" {
			return "", "", errors.New("missing signature in request")
		}

		pgpSig, err := crypto.NewPGPSignatureFromArmored(sigText)
		if err != nil {
			return "", "", err
		}

		// Use as public key
		signRing, err := crypto.NewKeyRing(key)
		if err != nil {
			return "", "", err
		}

		if err := signRing.VerifyDetached(
			crypto.NewPlainMessage(data),
			pgpSig, crypto.GetUnixTime(),
		); err != nil {
			return "", "", err
		}

		return sigText, fingerprint, nil
	}

	// Sign ourself

	if passwd := r.FormValue("passphrase"); !c.cfg.NoPassphrase && passwd != "" {
		if key, err = key.Unlock([]byte(passwd)); err != nil {
			return "", "", err
		}
	}

	// Use as private key
	signRing, err := crypto.NewKeyRing(key)
	if err != nil {
		return "", "", err
	}

	sig, err := signRing.SignDetached(crypto.NewPlainMessage(data))
	if err != nil {
		return "", "", err
	}

	armored, err := sig.GetArmored()
	return armored, fingerprint, err
}

func (c *controller) upload(rw http.ResponseWriter, r *http.Request) {

	newCSAF, data, err := loadCSAF(r)
	if err != nil {
		c.failed(rw, "upload.html", err)
		return
	}

	var content interface{}
	if err := json.Unmarshal(data, &content); err != nil {
		c.failed(rw, "upload.html", err)
		return
	}

	ex, err := newExtraction(content)
	if err != nil {
		c.failed(rw, "upload.html", err)
		return
	}

	t, err := c.tlpParam(r)
	if err != nil {
		c.failed(rw, "upload.html", err)
		return
	}

	// Extract real TLP from document.
	if t == tlpCSAF {
		if t = tlp(strings.ToLower(ex.tlpLabel)); !t.valid() || t == tlpCSAF {
			c.failed(
				rw, "upload.html", fmt.Errorf("not a valid TL: %s", ex.tlpLabel))
			return
		}
	}

	armored, fingerprint, err := c.handleSignature(r, data)
	if err != nil {
		c.failed(rw, "upload.html", err)
		return
	}

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

			year := strconv.Itoa(ex.currentReleaseDate.Year())

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
			if err := saveToFile(feed, rolie); err != nil {
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
			// TODO: Check for conflicts.
			pmd.Publisher = ex.publisher

			pmd.SetPGP(fingerprint, c.cfg.GetPGPURL(fingerprint))

			return nil
		}); err != nil {
		c.failed(rw, "upload.html", err)
		return
	}

	result := map[string]interface{}{
		"Name":        newCSAF,
		"ReleaseDate": ex.currentReleaseDate.Format(dateFormat),
	}

	c.render(rw, "upload.html", result)
}
