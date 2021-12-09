package main

import (
	"bytes"
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
	"github.com/jessevdk/go-flags"
	"github.com/mitchellh/go-homedir"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh/terminal"
)

type options struct {
	Action         string `short:"a" long:"action" choice:"upload" choice:"create" default:"upload" description:"Action to perform"`
	URL            string `short:"u" long:"url" description:"URL of the CSAF provider" default:"https://localhost/cgi-bin/csaf_provider.go" value-name:"URL"`
	TLP            string `short:"t" long:"tlp" choice:"csaf" choice:"white" choice:"green" choice:"amber" choice:"red" default:"csaf" description:"TLP of the feed"`
	ExternalSigned bool   `short:"x" long:"external-signed" description:"CASF files are signed externally. Assumes .asc files beside CSAF files."`
	NoSchemaCheck  bool   `short:"s" long:"no-schema-check" description:"Do not check files against CSAF JSON schema locally."`

	Key        *string `short:"k" long:"key" description:"OpenPGP key to sign the CSAF files" value-name:"KEY-FILE"`
	Password   *string `short:"p" long:"password" description:"Authentication password for accessing the CSAF provider" value-name:"PASSWORD"`
	Passphrase *string `short:"P" long:"passphrase" description:"Passphrase to unlock the OpenPGP key" value-name:"PASSPHRASE"`

	PasswordInteractive   bool `short:"i" long:"password-interactive" description:"Enter password interactively" no-ini:"true"`
	PassphraseInteractive bool `short:"I" long:"passphrase-interacive" description:"Enter passphrase interactively" no-ini:"true"`

	Config *string `short:"c" long:"config" description:"Path to config ini file" value-name:"INI-FILE" no-ini:"true"`
}

type processor struct {
	opts       *options
	cachedAuth string
	keyRing    *crypto.KeyRing
}

var iniPaths = []string{
	"~/.config/csaf/uploader.ini",
	"~/.csaf_uploader.ini",
	"csaf_uploader.ini",
}

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

func writeStrings(header string, messages []string) {
	if len(messages) > 0 {
		fmt.Println(header)
		for _, msg := range messages {
			fmt.Printf("\t%s\n", msg)
		}
	}
}

func (p *processor) create() error {
	req, err := http.NewRequest(http.MethodGet, p.opts.URL+"/api/create", nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-CSAF-PROVIDER-AUTH", p.cachedAuth)

	resp, err := http.DefaultClient.Do(req)
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

func (p *processor) process(filename string) error {

	req, err := p.uploadRequest(filename)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Upload failed: %s\n", resp.Status)
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

	return nil
}

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

func readInteractive(prompt string, pw **string) error {
	fmt.Print(prompt)
	p, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return err
	}
	ps := string(p)
	*pw = &ps
	return nil
}

func check(err error) {
	if err != nil {
		log.Fatalf("error: %v\n", err)
	}
}

func checkParser(err error) {
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
	checkParser(err)

	if opts.Config != nil {
		iniParser := flags.NewIniParser(parser)
		iniParser.ParseAsDefaults = true
		name, err := homedir.Expand(*opts.Config)
		check(err)
		checkParser(iniParser.ParseFile(name))
	} else if iniFile := findIniFile(); iniFile != "" {
		iniParser := flags.NewIniParser(parser)
		iniParser.ParseAsDefaults = true
		checkParser(iniParser.ParseFile(iniFile))
	}

	if opts.PasswordInteractive {
		check(readInteractive("Enter auth password: ", &opts.Password))
	}

	if opts.PassphraseInteractive {
		check(readInteractive("Enter OpenPGP passphrase: ", &opts.Passphrase))
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
