package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/crypto"

	"github.com/intevation/csaf_trusted/csaf"
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

func writeHash(fname, name string, h hash.Hash, data []byte) error {

	if _, err := io.Copy(h, bytes.NewReader(data)); err != nil {
		return err
	}

	f, err := os.Create(fname)
	if err != nil {
		return err
	}
	fmt.Fprintf(f, "%x %s\n", h.Sum(nil), name)
	return f.Close()
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

	if err := c.doTransaction(t, func(folder string, pmd *csaf.ProviderMetadata) error {

		year := strconv.Itoa(ex.currentReleaseDate.Year())

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

		// Write the file itself.
		if err := ioutil.WriteFile(fname, data, 0644); err != nil {
			return err
		}

		// Write SHA256 sum.
		if err := writeHash(fname+".sha256", newCSAF, sha256.New(), data); err != nil {
			return err
		}

		// Write SHA512 sum.
		if err := writeHash(fname+".sha512", newCSAF, sha512.New(), data); err != nil {
			return err
		}

		// Write signature.
		if err := ioutil.WriteFile(fname+".asc", []byte(armored), 0644); err != nil {
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

func (c *controller) doTransaction(
	t tlp,
	fn func(string, *csaf.ProviderMetadata) error,
) error {

	wellknown := filepath.Join(c.cfg.Web, ".well-known", "csaf")

	metadata := filepath.Join(wellknown, "provider-metadata.json")

	pmd, err := func() (*csaf.ProviderMetadata, error) {
		f, err := os.Open(metadata)
		if err != nil {
			if os.IsNotExist(err) {
				return csaf.NewProviderMetadata(
					c.cfg.Domain + "/.wellknown/csaf/provider-metadata.json"), nil
			}
			return nil, err
		}
		defer f.Close()
		return csaf.LoadProviderMetadata(f)
	}()

	if err != nil {
		return err
	}

	webTLP := filepath.Join(wellknown, string(t))

	oldDir, err := filepath.EvalSymlinks(webTLP)
	if err != nil {
		return err
	}

	folderTLP := filepath.Join(c.cfg.Folder, string(t))

	newDir, err := mkUniqDir(folderTLP)
	if err != nil {
		return err
	}

	// Copy old content into new.
	if err := deepCopy(newDir, oldDir); err != nil {
		os.RemoveAll(newDir)
		return err
	}

	// Work with new folder.
	if err := fn(newDir, pmd); err != nil {
		os.RemoveAll(newDir)
		return err
	}

	// Write back provider metadata.
	newMetaName, newMetaFile, err := mkUniqFile(metadata)
	if err != nil {
		os.RemoveAll(newDir)
		return err
	}

	if err := pmd.Save(newMetaFile); err != nil {
		newMetaFile.Close()
		os.Remove(newMetaName)
		os.RemoveAll(newDir)
		return err
	}

	if err := newMetaFile.Close(); err != nil {
		os.Remove(newMetaName)
		os.RemoveAll(newDir)
		return err
	}

	if err := os.Rename(newMetaName, metadata); err != nil {
		os.RemoveAll(newDir)
		return err
	}

	// Switch directories.
	symlink := filepath.Join(newDir, string(t))
	if err := os.Symlink(newDir, symlink); err != nil {
		os.RemoveAll(newDir)
		return err
	}
	if err := os.Rename(symlink, webTLP); err != nil {
		os.RemoveAll(newDir)
		return err
	}

	return os.RemoveAll(oldDir)
}
