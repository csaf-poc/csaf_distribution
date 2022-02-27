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
	// The environment name, that contains the path to the config file.
	configEnv          = "CSAF_CONFIG"
	defaultConfigPath  = "/usr/lib/csaf/config.toml"                                        // Default path to the config file.
	defaultFolder      = "/var/www/"                                                        // Default folder path.
	defaultWeb         = "/var/www/html"                                                    // Default web path.
	defaultOpenPGPURL  = "https://openpgp.circl.lu/pks/lookup?op=get&search=${FINGERPRINT}" // Default OpenPGP URL.
	defaultUploadLimit = 50 * 1024 * 1024                                                   // Default limit size of the uploaded file.
)

// configs contains the config values for the provider.
type config struct {
	Password                *string         `toml:"password"`
	Key                     string          `toml:"key"`
	Folder                  string          `toml:"folder"`
	Web                     string          `toml:"web"`
	TLPs                    []tlp           `toml:"tlps"`
	UploadSignature         bool            `toml:"upload_signature"`
	OpenPGPURL              string          `toml:"openpgp_url"`
	Domain                  string          `toml:"domain"`
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

// valid returns true if the checked tlp matches one of the defined tlps.
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

// uploadLimiter returns a reader that reads from a given r reader but stops
// with EOF after the defined bytes in the "UploadLimit" config option.
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

// loadCryptoKey loads the armored data into the key stored in the file specified by the
// "key" config value and return it with nil, otherwise an error.
func (cfg *config) loadCryptoKey() (*crypto.Key, error) {
	f, err := os.Open(cfg.Key)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return crypto.NewKeyFromArmoredReader(f)
}

// checkPassword compares the given hashed password with the plaintext in the "password" config value.
// It returns true if these matches or if the "password" config value is not set, otherwise false.
func (cfg *config) checkPassword(hash string) bool {
	return cfg.Password == nil ||
		bcrypt.CompareHashAndPassword([]byte(hash), []byte(*cfg.Password)) == nil
}

// loadConfig extracts the config values from the config file. The path to the
// file is taken either from environment variable "CSAF_CONFIG" or from the
// defined default path in "defaultConfigPath".
// Default values are set in case some are missing in the file.
// It returns these values in a struct and nil if there is no error.
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

	if cfg.Domain == "" {
		cfg.Domain = "http://" + os.Getenv("SERVER_NAME")
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
