// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/csaf-poc/csaf_distribution/csaf"
	"golang.org/x/crypto/bcrypt"
)

const (
	configEnv          = "CSAF_CONFIG"
	defaultConfigPath  = "/usr/lib/casf/config.toml"
	defaultFolder      = "/var/www/"
	defaultWeb         = "/var/www/html"
	defaultOpenPGPURL  = "https://openpgp.circl.lu/pks/lookup?op=get&search=${FINGERPRINT}"
	defaultUploadLimit = 50 * 1024 * 1024
)

type config struct {
	Password                *string         `toml:"password"`
	Key                     string          `toml:"key"`
	Folder                  string          `toml:"folder"`
	Web                     string          `toml:"web"`
	TLPs                    []tlp           `toml:"tlps"`
	UploadSignature         bool            `toml:"upload_signature"`
	OpenPGPURL              string          `toml:"openpgp_url"`
	CanonicalURLPrefix      string          `toml:"canonical_url_prefix"`
	NoPassphrase            bool            `toml:"no_passphrase"`
	NoValidation            bool            `toml:"no_validation"`
	NoWebUI                 bool            `toml:"no_web_ui"`
	DynamicProviderMetaData bool            `toml:"dynamic_provider_metadata"`
	Publisher               *csaf.Publisher `toml:"publisher"`
	UploadLimit             *int64          `toml:"upload_limit"`
}

type tlp string

const (
	tlpCSAF  tlp = "csaf"
	tlpWhite tlp = "white"
	tlpGreen tlp = "green"
	tlpAmber tlp = "amber"
	tlpRed   tlp = "red"
)

func (t tlp) valid() bool {
	switch t {
	case tlpCSAF, tlpWhite, tlpGreen, tlpAmber, tlpRed:
		return true
	default:
		return false
	}
}

func (t *tlp) UnmarshalText(text []byte) error {
	if s := tlp(text); s.valid() {
		*t = s
		return nil
	}
	return fmt.Errorf("invalid config TLP value: %v", string(text))
}

func (cfg *config) uploadLimiter(r io.Reader) io.Reader {
	// Zero or less means no upload limit.
	if cfg.UploadLimit == nil || *cfg.UploadLimit < 1 {
		return r
	}
	return io.LimitReader(r, *cfg.UploadLimit)
}

func (cfg *config) GetOpenPGPURL(key *crypto.Key) string {
	if key == nil {
		return cfg.OpenPGPURL
	}
	return strings.NewReplacer(
		"${FINGERPRINT}", "0x"+key.GetFingerprint(),
		"${KEY_ID}", "0x"+key.GetHexKeyID()).Replace(cfg.OpenPGPURL)
}

func (cfg *config) modelTLPs() []csaf.TLPLabel {
	tlps := make([]csaf.TLPLabel, 0, len(cfg.TLPs))
	for _, t := range cfg.TLPs {
		if t != tlpCSAF {
			tlps = append(tlps, csaf.TLPLabel(strings.ToUpper(string(t))))
		}
	}
	return tlps
}

func (cfg *config) loadCryptoKey() (*crypto.Key, error) {
	f, err := os.Open(cfg.Key)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return crypto.NewKeyFromArmoredReader(f)
}

func (cfg *config) checkPassword(hash string) bool {
	return cfg.Password == nil ||
		bcrypt.CompareHashAndPassword([]byte(hash), []byte(*cfg.Password)) == nil
}

func loadConfig() (*config, error) {
	path := os.Getenv(configEnv)
	if path == "" {
		path = defaultConfigPath
	}
	var cfg config
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, err
	}

	// Preset defaults

	if cfg.Folder == "" {
		cfg.Folder = defaultFolder
	}

	if cfg.Web == "" {
		cfg.Web = defaultWeb
	}

	if cfg.CanonicalURLPrefix == "" {
		cfg.CanonicalURLPrefix = "https://" + os.Getenv("SERVER_NAME")
	}

	if cfg.TLPs == nil {
		cfg.TLPs = []tlp{tlpCSAF, tlpWhite, tlpGreen, tlpAmber, tlpRed}
	}

	if cfg.OpenPGPURL == "" {
		cfg.OpenPGPURL = defaultOpenPGPURL
	}

	if cfg.Publisher == nil {
		cfg.Publisher = &csaf.Publisher{
			Category:  func(c csaf.Category) *csaf.Category { return &c }(csaf.CSAFCategoryVendor),
			Name:      func(s string) *string { return &s }("ACME"),
			Namespace: func(s string) *string { return &s }("https://example.com"),
		}
	}

	if cfg.UploadLimit == nil {
		ul := int64(defaultUploadLimit)
		cfg.UploadLimit = &ul
	}

	return &cfg, nil
}
