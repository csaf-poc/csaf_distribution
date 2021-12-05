package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/csaf-poc/csaf_distribution/csaf"
)

const (
	configEnv         = "CSAF_CONFIG"
	defaultConfigPath = "/usr/lib/casf/config.toml"
	defaultFolder     = "/var/www/"
	defaultWeb        = "/var/www/html"
	defaultOpenPGPURL = "https://openpgp.circl.lu/pks/lookup?search=${KEY}&op=index"
)

type config struct {
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

func (cfg *config) GetOpenPGPURL(key string) string {
	return strings.ReplaceAll(cfg.OpenPGPURL, "${KEY}", "0x"+key)
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

	return &cfg, nil
}
