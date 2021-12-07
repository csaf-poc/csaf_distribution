package main

import (
	"fmt"
	"log"
	"os"

	"github.com/jessevdk/go-flags"
	"github.com/mitchellh/go-homedir"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh/terminal"
)

type options struct {
	URL                   string  `short:"u" long:"url" description:"URL of the CSAF provider" default:"https://localhost/cgi-bin/csaf_provider.go" value-name:"URL"`
	Password              *string `short:"p" long:"password" description:"Authentication password for accessing the CSAF provider" value-name:"PASSWORD"`
	Key                   *string `short:"k" long:"key" description:"OpenPGP key to sign the CSAF files" value-name:"KEY-FILE"`
	Passphrase            *string `short:"P" long:"passphrase" description:"Passphrase to unlock the OpenPGP key" value-name:"PASSPHRASE"`
	Action                string  `short:"a" long:"action" choice:"upload" choice:"create" default:"upload" description:"Action to perform"`
	Config                *string `short:"c" long:"config" description:"Path to config ini file" value-name:"INI-FILE"`
	PasswordInteractive   bool    `short:"i" long:"password-interactive" description:"Enter password interactively" no-ini:"true"`
	PassphraseInteractive bool    `short:"I" long:"passphrase-interacive" description:"Enter passphrase interactively" no-ini:"true"`
}

type processor struct {
	opts       *options
	cachedAuth string
}

var iniPaths = []string{
	"~/.config/csaf/uploader.ini",
	"~/.csaf_uploader.ini",
	"csaf_uploader.ini",
}

func newProcessor(opts *options) (*processor, error) {
	p := processor{
		opts: opts,
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
	// TODO: Implement me!
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
