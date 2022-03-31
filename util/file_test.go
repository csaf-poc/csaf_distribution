package util

import (
	"bytes"
	"testing"
)

func TestNWriter(t *testing.T) {

	msg := []byte("Gruß!\n")

	first, second := msg[:len(msg)/2], msg[len(msg)/2:]

	var buf bytes.Buffer
	nw := NWriter{Writer: &buf, N: 0}
	_, err1 := nw.Write(first)
	_, err2 := nw.Write(second)

	if err1 != nil || err2 != nil {
		t.Error("Calling NWriter failed")
	}

	if n := int64(len(msg)); nw.N != n {
		t.Errorf("Expected %d bytes, but counted %d.", n, nw.N)
	}

	if out := buf.Bytes(); !bytes.Equal(msg, out) {
		t.Errorf("Expected %q, but got %q", msg, out)
	}
}
