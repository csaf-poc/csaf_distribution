package main

import (
	"os"
	"testing"
)

// call realMain() with Args that skip over params used by "go test"
// allow calls like
//   go test -c -vet=off -covermode=atomic -o csaf_uploader.debug
//  ./csaf_uploader.debug -test.coverprofile=/tmp/csaf_uploader-itest-${EPOCHREALTIME}.cov -- --insecure ....
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
	realMain(os.Args[endOfTestParams+1:])
}
