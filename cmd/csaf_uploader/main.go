// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

// Implements a command line tool that uploads csaf documents to csaf_provider.
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/csaf-poc/csaf_distribution/csaf"
	"github.com/csaf-poc/csaf_distribution/util"
	"github.com/jessevdk/go-flags"
	"github.com/mitchellh/go-homedir"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

// The supported flag options of the uploader command line
type options struct {
	Action         string `short:"a" long:"action" choice:"upload" choice:"create" default:"upload" description:"Action to perform"`
	URL            string `short:"u" long:"url" description:"URL of the CSAF provider" default:"https://localhost/cgi-bin/csaf_provider.go" value-name:"URL"`
	TLP            string `short:"t" long:"tlp" choice:"csaf" choice:"white" choice:"green" choice:"amber" choice:"red" default:"csaf" description:"TLP of the feed"`
	ExternalSigned bool   `short:"x" long:"external-signed" description:"CSAF files are signed externally. Assumes .asc files beside CSAF files."`
	NoSchemaCheck  bool   `short:"s" long:"no-schema-check" description:"Do not check files against CSAF JSON schema locally."`

	Key        *string `short:"k" long:"key" description:"OpenPGP key to sign the CSAF files" value-name:"KEY-FILE"`
	Password   *string `short:"p" long:"password" description:"Authentication password for accessing the CSAF provider" value-name:"PASSWORD"`
	Passphrase *string `short:"P" long:"passphrase" description:"Passphrase to unlock the OpenPGP key" value-name:"PASSPHRASE"`
	ClientCert *string `long:"client-cert" description:"TLS client certificate file (PEM encoded data)" value-name:"CERT-FILE.crt"`
	ClientKey  *string `long:"client-key" description:"TLS client private key file (PEM encoded data)" value-name:"KEY-FILE.pem"`

	PasswordInteractive   bool `short:"i" long:"password-interactive" description:"Enter password interactively" no-ini:"true"`
	PassphraseInteractive bool `short:"I" long:"passphrase-interactive" description:"Enter OpenPGP key passphrase interactively" no-ini:"true"`

	Insecure bool `long:"insecure" description:"Do not check TLS certificates from provider"`

	Config  *string `short:"c" long:"config" description:"Path to config ini file" value-name:"INI-FILE" no-ini:"true"`
	Version bool    `long:"version" description:"Display version of the binary"`
}

type processor struct {
	opts       *options
	cachedAuth string
	keyRing    *crypto.KeyRing
}

// iniPaths are the potential file locations of the the config file.
var iniPaths = []string{
	"~/.config/csaf/uploader.ini",
	"~/.csaf_uploader.ini",
	"csaf_uploader.ini",
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

func newProcessor(opts *options) (*processor, error) {
	p := processor{
		opts: opts,
	}

	if opts.Action == "upload" {
		if opts.Key != nil {
			if opts.ExternalSigned {
				return nil, errors.New("refused to sign external signed files")
			}
			var err error
			var key *crypto.Key
			if key, err = loadKey(*opts.Key); err != nil {
				return nil, err
			}
			if opts.Passphrase != nil {
				if key, err = key.Unlock([]byte(*opts.Passphrase)); err != nil {
					return nil, err
				}
			}
			if p.keyRing, err = crypto.NewKeyRing(key); err != nil {
				return nil, err
			}
		}
	}

	// pre-calc the auth header
	if opts.Password != nil {
		hash, err := bcrypt.GenerateFromPassword(
			[]byte(*opts.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		p.cachedAuth = string(hash)
	}

	return &p, nil
}

// httpClient initializes the http.Client according to the "Insecure" flag
// and the TLS client files for authentication and returns it.
func (p *processor) httpClient() *http.Client {
	var client http.Client
	var tlsConfig tls.Config

	if p.opts.Insecure {
		tlsConfig.InsecureSkipVerify = true
	}

	if p.opts.ClientCert != nil && p.opts.ClientKey != nil {
		cert, err := tls.LoadX509KeyPair(*p.opts.ClientCert, *p.opts.ClientKey)
		if err != nil {
			log.Fatal(err)
		}

		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	client.Transport = &http.Transport{
		TLSClientConfig: &tlsConfig,
	}

	return &client
}

// writeStrings prints the passed messages under the specific passed header.
func writeStrings(header string, messages []string) {
	if len(messages) > 0 {
		fmt.Println(header)
		for _, msg := range messages {
			fmt.Printf("\t%s\n", msg)
		}
	}
}

// create sends an request to create the initial files and directories
// on the server. It prints the response messages.
func (p *processor) create() error {
	req, err := http.NewRequest(http.MethodGet, p.opts.URL+"/api/create", nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-CSAF-PROVIDER-AUTH", p.cachedAuth)

	resp, err := p.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Create failed: %s\n", resp.Status)
	}

	var result struct {
		Message string   `json:"message"`
		Errors  []string `json:"errors"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	if result.Message != "" {
		fmt.Printf("\t%s\n", result.Message)
	}

	writeStrings("Errors:", result.Errors)

	return nil
}

// uploadRequest creates the request for uploading a csaf document by passing the filename.
// According to the flags values the multipart sections of the request are established.
// It returns the created http request.
func (p *processor) uploadRequest(filename string) (*http.Request, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	if !p.opts.NoSchemaCheck {
		var doc interface{}
		if err := json.NewDecoder(bytes.NewReader(data)).Decode(&doc); err != nil {
			return nil, err
		}
		errs, err := csaf.ValidateCSAF(doc)
		if err != nil {
			return nil, err
		}
		if len(errs) > 0 {
			writeStrings("Errors:", errs)
			return nil, errors.New("local schema check failed")
		}
	}

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("csaf", filepath.Base(filename))
	if err != nil {
		return nil, err
	}

	if _, err := part.Write(data); err != nil {
		return nil, err
	}

	if err := writer.WriteField("tlp", p.opts.TLP); err != nil {
		return nil, err
	}

	if p.keyRing == nil && p.opts.Passphrase != nil {
		if err := writer.WriteField("passphrase", *p.opts.Passphrase); err != nil {
			return nil, err
		}
	}

	if p.keyRing != nil {
		sig, err := p.keyRing.SignDetached(crypto.NewPlainMessage(data))
		if err != nil {
			return nil, err
		}
		armored, err := sig.GetArmored()
		if err != nil {
			return nil, err
		}
		if err := writer.WriteField("signature", armored); err != nil {
			return nil, err
		}
	}

	if p.opts.ExternalSigned {
		signature, err := os.ReadFile(filename + ".asc")
		if err != nil {
			return nil, err
		}
		if err := writer.WriteField("signature", string(signature)); err != nil {
			return nil, err
		}
	}

	if err := writer.Close(); err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, p.opts.URL+"/api/upload", body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-CSAF-PROVIDER-AUTH", p.cachedAuth)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	return req, nil
}

// process attemps to upload a file to the server.
// It prints the response messages.
func (p *processor) process(filename string) error {

	if bn := filepath.Base(filename); !util.ConfirmingFileName(bn) {
		return fmt.Errorf("%q is not a confirming file name", bn)
	}

	req, err := p.uploadRequest(filename)
	if err != nil {
		return err
	}

	resp, err := p.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var uploadErr error
	if resp.StatusCode != http.StatusOK {
		uploadErr = fmt.Errorf("upload failed: %s", resp.Status)
		fmt.Printf("HTTPS %s\n", uploadErr)
	}

	var result struct {
		Name        string   `json:"name"`
		ReleaseDate string   `json:"release_date"`
		Warnings    []string `json:"warnings"`
		Errors      []string `json:"errors"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	if result.Name != "" {
		fmt.Printf("Name: %s\n", result.Name)
	}
	if result.ReleaseDate != "" {
		fmt.Printf("Release date: %s\n", result.ReleaseDate)
	}

	writeStrings("Warnings:", result.Warnings)
	writeStrings("Errors:", result.Errors)

	return uploadErr
}

// findIniFile looks for a file in the pre-defined paths in "iniPaths".
// The returned value will be the name of file if found, otherwise an empty string.
func findIniFile() string {
	for _, f := range iniPaths {
		name, err := homedir.Expand(f)
		if err != nil {
			log.Printf("warn: %v\n", err)
			continue
		}
		if _, err := os.Stat(name); err == nil {
			return name
		}
	}
	return ""
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

func check(err error) {
	if err != nil {
		if e, ok := err.(*flags.Error); ok && e.Type == flags.ErrHelp {
			os.Exit(0)
		}
		log.Fatalf("error: %v\n", err)
	}
}

func main() {
	var opts options

	parser := flags.NewParser(&opts, flags.Default)

	args, err := parser.Parse()
	check(err)

	if opts.Version {
		fmt.Println(util.SemVersion)
		return
	}

	if opts.Config != nil {
		iniParser := flags.NewIniParser(parser)
		iniParser.ParseAsDefaults = true
		name, err := homedir.Expand(*opts.Config)
		check(err)
		check(iniParser.ParseFile(name))
	} else if iniFile := findIniFile(); iniFile != "" {
		iniParser := flags.NewIniParser(parser)
		iniParser.ParseAsDefaults = true
		check(iniParser.ParseFile(iniFile))
	}

	if opts.PasswordInteractive {
		check(readInteractive("Enter auth password: ", &opts.Password))
	}

	if opts.PassphraseInteractive {
		check(readInteractive("Enter OpenPGP passphrase: ", &opts.Passphrase))
	}

	if opts.ClientCert != nil && opts.ClientKey == nil || opts.ClientCert == nil && opts.ClientKey != nil {
		log.Println("Both client-key and client-cert options must be set for the authentication.")
		return
	}

	p, err := newProcessor(&opts)
	check(err)

	if opts.Action == "create" {
		check(p.create())
		return
	}

	if len(args) == 0 {
		log.Println("No CSAF files given.")
	}

	for _, arg := range args {
		check(p.process(arg))
	}
}
