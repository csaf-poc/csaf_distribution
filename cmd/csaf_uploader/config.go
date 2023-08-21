// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2023 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2023 Intevation GmbH <https://intevation.de>

package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/csaf-poc/csaf_distribution/v2/internal/certs"
	"github.com/csaf-poc/csaf_distribution/v2/internal/options"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

const (
	defaultURL    = "https://localhost/cgi-bin/csaf_provider.go"
	defaultAction = "upload"
	defaultTLP    = "csaf"
)

// The supported flag config of the uploader command line
type config struct {
	//lint:ignore SA5008 We are using choice twice: upload, create.
	Action string `short:"a" long:"action" choice:"upload" choice:"create" description:"Action to perform"`
	URL    string `short:"u" long:"url" description:"URL of the CSAF provider" value-name:"URL"`
	//lint:ignore SA5008 We are using choice many times: csaf, white, green, amber, red.
	TLP            string `short:"t" long:"tlp" choice:"csaf" choice:"white" choice:"green" choice:"amber" choice:"red" description:"TLP of the feed"`
	ExternalSigned bool   `short:"x" long:"external-signed" description:"CSAF files are signed externally. Assumes .asc files beside CSAF files."`
	NoSchemaCheck  bool   `short:"s" long:"no-schema-check" description:"Do not check files against CSAF JSON schema locally."`

	Key              *string `short:"k" long:"key" description:"OpenPGP key to sign the CSAF files" value-name:"KEY-FILE"`
	Password         *string `short:"p" long:"password" description:"Authentication password for accessing the CSAF provider" value-name:"PASSWORD"`
	Passphrase       *string `short:"P" long:"passphrase" description:"Passphrase to unlock the OpenPGP key" value-name:"PASSPHRASE"`
	ClientCert       *string `long:"client-cert" description:"TLS client certificate file (PEM encoded data)" value-name:"CERT-FILE.crt"`
	ClientKey        *string `long:"client-key" description:"TLS client private key file (PEM encoded data)" value-name:"KEY-FILE.pem"`
	ClientPassphrase *string `long:"client-passphrase" description:"Optional passphrase for the client cert (limited, experimental, see downloader doc)" value-name:"PASSPHRASE"`

	PasswordInteractive   bool `short:"i" long:"password-interactive" description:"Enter password interactively" toml:"-"`
	PassphraseInteractive bool `short:"I" long:"passphrase-interactive" description:"Enter OpenPGP key passphrase interactively" toml:"-"`

	Insecure bool `long:"insecure" description:"Do not check TLS certificates from provider"`

	Config  string `short:"c" long:"config" description:"Path to config TOML file" value-name:"TOML-FILE" toml:"-"`
	Version bool   `long:"version" description:"Display version of the binary"`

	clientCerts []tls.Certificate
	cachedAuth  string
	keyRing     *crypto.KeyRing
}

// iniPaths are the potential file locations of the the config file.
var configPaths = []string{
	"~/.config/csaf/uploader.toml",
	"~/.csaf_uploader.toml",
	"csaf_uploader.toml",
}

// parseArgsConfig parses the command line and if need a config file.
func parseArgsConfig() ([]string, *config, error) {
	p := options.Parser[config]{
		DefaultConfigLocations: configPaths,
		ConfigLocation:         func(cfg *config) string { return cfg.Config },
		Usage:                  "[OPTIONS] advisories...",
		HasVersion:             func(cfg *config) bool { return cfg.Version },
		SetDefaults: func(cfg *config) {
			cfg.URL = defaultURL
			cfg.Action = defaultAction
			cfg.TLP = defaultTLP
		},
		// Re-establish default values if not set.
		EnsureDefaults: func(cfg *config) {
			if cfg.URL == "" {
				cfg.URL = defaultURL
			}
			if cfg.Action == "" {
				cfg.Action = defaultAction
			}
			if cfg.TLP == "" {
				cfg.TLP = defaultTLP
			}
		},
	}
	return p.Parse()
}

// prepareCertificates loads the client side certificates used by the HTTP client.
func (cfg *config) prepareCertificates() error {
	cert, err := certs.LoadCertificate(
		cfg.ClientCert, cfg.ClientKey, cfg.ClientPassphrase)
	if err != nil {
		return err
	}
	cfg.clientCerts = cert
	return nil
}

// readInteractive prints a message to command line and retrieves the password from it.
func readInteractive(prompt string, pw **string) error {
	fmt.Print(prompt)
	p, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return err
	}
	ps := string(p)
	*pw = &ps
	return nil
}

// prepareInteractive prompts for interactive passwords.
func (cfg *config) prepareInteractive() error {
	if cfg.PasswordInteractive {
		if err := readInteractive("Enter auth password: ", &cfg.Password); err != nil {
			return err
		}
	}
	if cfg.PassphraseInteractive {
		if err := readInteractive("Enter OpenPGP passphrase: ", &cfg.Passphrase); err != nil {
			return err
		}
	}
	return nil
}

// loadKey loads an OpenPGP key.
func loadKey(filename string) (*crypto.Key, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return crypto.NewKeyFromArmoredReader(f)
}

// prepareKey loads the configure OpenPGP key.
func (cfg *config) prepareKey() error {
	if cfg.Action != "upload" || cfg.Key == nil {
		return nil
	}
	if cfg.ExternalSigned {
		return errors.New("refused to sign external signed files")
	}
	var err error
	var key *crypto.Key
	if key, err = loadKey(*cfg.Key); err != nil {
		return err
	}
	if cfg.Passphrase != nil {
		if key, err = key.Unlock([]byte(*cfg.Passphrase)); err != nil {
			return err
		}
	}
	cfg.keyRing, err = crypto.NewKeyRing(key)
	return err
}

// preparePassword pre-calculates the auth header.
func (cfg *config) preparePassword() error {
	if cfg.Password != nil {
		hash, err := bcrypt.GenerateFromPassword(
			[]byte(*cfg.Password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		cfg.cachedAuth = string(hash)
	}
	return nil
}

// prepare prepares internal state of a loaded configuration.
func (cfg *config) prepare() error {
	for _, prepare := range []func(*config) error{
		(*config).prepareCertificates,
		(*config).prepareInteractive,
		(*config).prepareKey,
		(*config).preparePassword,
	} {
		if err := prepare(cfg); err != nil {
			return err
		}
	}
	return nil
}
