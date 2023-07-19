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
	"net/http"
)

type config struct {
	Output      string      `short:"o" long:"output" description:"File name of the generated report" value-name:"REPORT-FILE"`
	Format      string      `short:"f" long:"format" choice:"json" choice:"html" description:"Format of report" default:"json"`
	Insecure    bool        `long:"insecure" description:"Do not check TLS certificates from provider"`
	ClientCert  *string     `long:"client-cert" description:"TLS client certificate file (PEM encoded data)" value-name:"CERT-FILE"`
	ClientKey   *string     `long:"client-key" description:"TLS client private key file (PEM encoded data)" value-name:"KEY-FILE"`
	Version     bool        `long:"version" description:"Display version of the binary"`
	Verbose     bool        `long:"verbose" short:"v" description:"Verbose output"`
	Rate        *float64    `long:"rate" short:"r" description:"The average upper limit of https operations per second (defaults to unlimited)"`
	Years       *uint       `long:"years" short:"y" description:"Number of years to look back from now" value-name:"YEARS"`
	ExtraHeader http.Header `long:"header" short:"H" description:"One or more extra HTTP header fields"`

	RemoteValidator        string   `long:"validator" description:"URL to validate documents remotely" value-name:"URL"`
	RemoteValidatorCache   string   `long:"validatorcache" description:"FILE to cache remote validations" value-name:"FILE"`
	RemoteValidatorPresets []string `long:"validatorpreset" description:"One or more presets to validate remotely" default:"mandatory"`

	clientCerts []tls.Certificate
}

// protectedAccess returns true if we have client certificates or
// extra http headers configured.
// This may be a wrong assumption, because the certs are not checked
// for their domain and custom headers may have other purposes.
func (cfg *config) protectedAccess() bool {
	return len(cfg.clientCerts) > 0 || len(cfg.ExtraHeader) > 0
}

func (cfg *config) prepare() error {
	// Load client certs.
	switch hasCert, hasKey := cfg.ClientCert != nil, cfg.ClientKey != nil; {

	case hasCert && !hasKey || !hasCert && hasKey:
		return errors.New("both client-key and client-cert options must be set for the authentication")

	case hasCert:
		cert, err := tls.LoadX509KeyPair(*cfg.ClientCert, *cfg.ClientKey)
		if err != nil {
			return err
		}
		cfg.clientCerts = []tls.Certificate{cert}
	}
	return nil
}
