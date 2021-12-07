package main

import (
	"log"
	"os"

	"github.com/jessevdk/go-flags"
	"github.com/mitchellh/go-homedir"
)

type options struct {
	URL        string  `short:"u" long:"url" description:"URL of the CSAF provider" default:"https://localhost/cgi-bin/csaf_provider.go" value-name:"URL"`
	Password   *string `short:"P" long:"password" description:"Authentication password for accessing the CSAF provider" value-name:"PASSWORD"`
	Key        *string `short:"k" long:"key" description:"OpenPGP key to sign the CSAF files" value-name:"KEY-FILE"`
	Passphrase *string `short:"p" long:"passphrase" description:"Passphrase to unlock the OpenPGP key" value-name:"PASSPHRASE"`
	Action     string  `short:"a" long:"action" choice:"upload" choice:"create" default:"upload" description:"Action to perform"`
	Config     *string `short:"c" long:"config" description:"Path to config ini file" value-name:"INI-FILE"`
}

var iniPaths = []string{
	"~/.config/csaf/uploader.ini",
	"~/.csaf_uploader.ini",
	"csaf_uploader.ini",
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

func main() {
	var opts options

	parser := flags.NewParser(&opts, flags.Default)

	args, err := parser.Parse()
	if err != nil {
		if e, ok := err.(*flags.Error); ok && e.Type == flags.ErrHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}

	if opts.Config != nil {
		iniParser := flags.NewIniParser(parser)
		iniParser.ParseAsDefaults = true
		name, err := homedir.Expand(*opts.Config)
		if err != nil {
			log.Fatalf("error: %v\n", err)
		}
		if err := iniParser.ParseFile(name); err != nil {
			os.Exit(1)
		}
	} else if iniFile := findIniFile(); iniFile != "" {
		iniParser := flags.NewIniParser(parser)
		iniParser.ParseAsDefaults = true
		if err := iniParser.ParseFile(iniFile); err != nil {
			os.Exit(1)
		}
	}

	if opts.Key != nil {
		log.Printf("key: %s\n", *opts.Key)
	}

	log.Printf("url: %s\n", opts.URL)
	log.Printf("action: %s\n", opts.Action)

	for _, arg := range args {
		log.Printf("arg: %s\n", arg)
	}
}
