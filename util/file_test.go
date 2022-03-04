package util

import (
	"bytes"
	"fmt"
	"testing"
)

func TestNWriter(t *testing.T) {
	var buf bytes.Buffer

	nw := NWriter{Writer: &buf, N: 0}
	_, err1 := fmt.Fprintf(&nw, "Gruß") // assuming 5 byte utf-8 output
	_, err2 := fmt.Fprintf(&nw, "!\n")  // assuming one byte line-ending

	if err1 != nil || err2 != nil {
		t.Error("Calling NWriter failed")
	}

	if nw.N != 7 {
		t.Errorf("Expected %d bytes, but counted %d", 7, nw.N)
	}
}
