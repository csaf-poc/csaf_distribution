package main

import (
	"os"

	"github.com/jessevdk/go-flags"
)

type options struct {
	Output string `short:"o" long:"output" description:"File name of the generated report" value-name:"REPORT-FILE"`
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

	args, err := flags.Parse(&opts)
	checkParser(err)

	_ = args

}
