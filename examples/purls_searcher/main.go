// Package main implements a simple demo program to
// work with the csaf_distribution library.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"slices"
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

	uf := newURLFinder(strings.Split(ids, ","))

	for _, file := range files {
		adv, err := csaf.LoadAdvisory(file)
		if err != nil {
			return fmt.Errorf("loading %q failed: %w", file, err)
		}
		uf.findURLs(adv)
		uf.dumpURLs()
		uf.clear()
	}

	return nil
}

// urlFinder helps to find the URLs of a set of product ids in advisories.
type urlFinder struct {
	ids  []csaf.ProductID
	urls [][]csaf.PURL
}

// newURLFinder creates a new urlFinder for given ids.
func newURLFinder(ids []string) *urlFinder {
	uf := &urlFinder{
		ids:  make([]csaf.ProductID, len(ids)),
		urls: make([][]csaf.PURL, len(ids)),
	}
	for i := range uf.ids {
		uf.ids[i] = csaf.ProductID(ids[i])
	}
	return uf
}

// clear resets the url finder after a run on an advisory.
func (uf *urlFinder) clear() {
	clear(uf.urls)
}

// dumpURLs dumps the found URLs to stdout.
func (uf *urlFinder) dumpURLs() {
	for i, urls := range uf.urls {
		if len(urls) == 0 {
			continue
		}
		fmt.Printf("Found URLs for %s:\n", uf.ids[i])
		for j, url := range urls {
			fmt.Printf("%d. %s\n", j+1, url)
		}
	}
}

// findURLs find the URLs in an advisory.
func (uf *urlFinder) findURLs(adv *csaf.Advisory) {
	tree := adv.ProductTree
	if tree == nil {
		return
	}

	// If we have found it and we have a valid URL add unique.
	add := func(idx int, h *csaf.ProductIdentificationHelper) {
		if idx != -1 && h != nil && h.PURL != nil &&
			!slices.Contains(uf.urls[idx], *h.PURL) {
			uf.urls[idx] = append(uf.urls[idx], *h.PURL)
		}
	}

	// First iterate over full product names.
	if names := tree.FullProductNames; names != nil {
		for _, name := range *names {
			if name != nil && name.ProductID != nil {
				add(slices.Index(uf.ids, *name.ProductID), name.ProductIdentificationHelper)
			}
		}
	}

	// Second traverse the branches recursively.
	var recBranch func(*csaf.Branch)
	recBranch = func(b *csaf.Branch) {
		if p := b.Product; p != nil && p.ProductID != nil {
			add(slices.Index(uf.ids, *p.ProductID), p.ProductIdentificationHelper)
		}
		for _, c := range b.Branches {
			recBranch(c)
		}
	}
	for _, b := range tree.Branches {
		recBranch(b)
	}

	// Third iterate over relationships.
	if tree.RelationShips != nil {
		for _, rel := range *tree.RelationShips {
			if rel != nil {
				if fpn := rel.FullProductName; fpn != nil && fpn.ProductID != nil {
					add(slices.Index(uf.ids, *fpn.ProductID), fpn.ProductIdentificationHelper)
				}
			}
		}
	}
}
