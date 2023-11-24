// Package main implements a simple demo program to
// work with the csaf_distribution library.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/csaf-poc/csaf_distribution/v3/csaf"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			"Usage:\n  %s [OPTIONS] files...\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
	}
	idsString := flag.String("p", "", "ID1,ID2,...")
	flag.Parse()

	files := flag.Args()
	if len(files) == 0 {
		log.Println("No files given.")
		return
	}
	if err := run(files, *idsString); err != nil {
		log.Fatalf("error: %v\n", err)
	}
}

// run prints PURLs belonging to the given Product IDs.
func run(files []string, ids string) error {
	for _, file := range files {
		adv, err := csaf.LoadAdvisory(file)
		if err != nil {
			return fmt.Errorf("loading %q failed: %w", file, err)
		}

		for _, id := range strings.Split(ids, ",") {
			for i, h := range adv.ProductTree.FindProductIdentificationHelpers(csaf.ProductID(id)) {
				if h.PURL != nil {
					fmt.Printf("%d. %s\n", i, *h.PURL)
				}
			}
		}
	}

	return nil
}
