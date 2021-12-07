package main

import (
	"fmt"
	"log"
	"os"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/jessevdk/go-flags"
	"github.com/mitchellh/go-homedir"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh/terminal"
)

type options struct {
	Action                string  `short:"a" long:"action" choice:"upload" choice:"create" default:"upload" description:"Action to perform"`
	URL                   string  `short:"u" long:"url" description:"URL of the CSAF provider" default:"https://localhost/cgi-bin/csaf_provider.go" value-name:"URL"`
	Password              *string `short:"p" long:"password" description:"Authentication password for accessing the CSAF provider" value-name:"PASSWORD"`
	Key                   *string `short:"k" long:"key" description:"OpenPGP key to sign the CSAF files" value-name:"KEY-FILE"`
	Passphrase            *string `short:"P" long:"passphrase" description:"Passphrase to unlock the OpenPGP key" value-name:"PASSPHRASE"`
	PasswordInteractive   bool    `short:"i" long:"password-interactive" description:"Enter password interactively" no-ini:"true"`
	PassphraseInteractive bool    `short:"I" long:"passphrase-interacive" description:"Enter passphrase interactively" no-ini:"true"`
	Config                *string `short:"c" long:"config" description:"Path to config ini file" value-name:"INI-FILE" no-ini:"true"`
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

func (p *processor) create() error {
	// TODO: Implement me!
	return nil
}

func (p *processor) process(filename string) error {

	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	var armored string
	if p.keyRing != nil {
		sig, err := p.keyRing.SignDetached(crypto.NewPlainMessage(data))
		if err != nil {
			return err
		}
		if armored, err = sig.GetArmored(); err != nil {
			return err
		}
	}
	// TODO: Implement me!
	_ = armored
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
		os.Exit(1)
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

	if opts.Key != nil {
		log.Printf("key: %s\n", *opts.Key)
	}

	log.Printf("url: %s\n", opts.URL)
	log.Printf("action: %s\n", opts.Action)

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

	for _, arg := range args {
		check(p.process(arg))
	}
}
