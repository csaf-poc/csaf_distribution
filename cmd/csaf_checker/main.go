package main

import (
	"encoding/json"
	"io"
	"log"
	"os"

	"github.com/jessevdk/go-flags"
)

type options struct {
	Output string `short:"o" long:"output" description:"File name of the generated report" value-name:"REPORT-FILE"`
	Format string `short:"f" long:"format" choice:"json" choice:"html" description:"Format of report" default:"json"`
}

var checks = []check{
	// TODO: Implement me!
}

func errCheck(err error) {
	if err != nil {
		if e, ok := err.(*flags.Error); ok && e.Type == flags.ErrHelp {
			os.Exit(0)
		}
		log.Fatalf("error: %v\n", err)
	}
}

func writeJSON(report *Report, w io.WriteCloser) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	err := enc.Encode(report)
	if e := w.Close(); err != nil {
		err = e
	}
	return err
}

func writeHTML(report *Report, w io.WriteCloser) error {
	// TODO: Implement me!
	return w.Close()
}

type nopCloser struct{ io.Writer }

func (nc *nopCloser) Close() error { return nil }

func writeReport(report *Report, opts *options) error {

	var w io.WriteCloser

	if opts.Output == "" {
		w = &nopCloser{os.Stdout}
	} else {
		f, err := os.Create(opts.Output)
		if err != nil {
			return err
		}
		w = f
	}

	var writer func(*Report, io.WriteCloser) error

	switch opts.Format {
	case "json":
		writer = writeJSON
	default:
		writer = writeHTML
	}

	return writer(report, w)
}

func main() {
	opts := new(options)

	domains, err := flags.Parse(opts)
	errCheck(err)

	if len(domains) == 0 {
		log.Println("No domains given.")
		return
	}

	report, err := run(domains, checks)
	errCheck(err)

	errCheck(writeReport(report, opts))
}
