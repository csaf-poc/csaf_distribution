package main

import (
	"os"
	"testing"
)

// as main() does not process os.Args, we can call it directly as -test.*
// parameters will be ignored.
//
// use like
//   go test -c -vet=off -covermode=atomic -o csaf_provider.debug
//   cp csaf_provider.debug /usr/lib/cgi-bin/
//
//   pushd /usr/lib/cgi-bin
//   mv csaf_provider.go csaf_provider2.go
//   echo '#!/bin/bash
//   exec /usr/lib/cgi-bin/csaf_provider.debug -test.coverprofile=/tmp/csaf_provider-itest.cov -- "$@"
//   ' >csaf_provider.go
//   chmod a+x csaf_provider.go
//
// then do a cgi-bin action on the provider like using the uploader

func TestMain(t *testing.T) {
	var endOfTestParams int
	for i, a := range os.Args[1:] {
		if a == "--" {
			endOfTestParams = i + 1
		}
	}

	if endOfTestParams == 0 {
		t.Skip("skipping integration test, no `--` parameter found")
	}
	main()
}
