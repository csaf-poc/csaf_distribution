package main

import (
	"os"
	"testing"
)

// call realMain() with Args that skip over params used by "go test"
// allow calls like
//   go test -c -vet=off -covermode=atomic  -o app.debug
//  ./app.debug -test.coverprofile=functest.cov -- --insecure localhost
func TestMain(t *testing.T) {
	var endOfTestParams int
	for i, a := range os.Args[1:] {
		if a == "--" {
			endOfTestParams = i + 1
		}
	}

	realMain(os.Args[endOfTestParams+1:])
}
