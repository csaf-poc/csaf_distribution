package util

import (
	"bytes"
	"testing"
)

func TestCleanFileName(t *testing.T) {
	for _, x := range [][2]string{
		{`HELLO`, `hello.json`},
		{`hello`, `hello.json`},
		{`cisco-sa-20190513-secureboot.json`, `cisco-sa-20190513-secureboot.json`},
		{``, `.json`},
		{`..`, `__.json`},
		{`../..`, `_____.json`},
		{`abc.html`, `________.json`},
		{`foo+BAR`, `foo+bar.json`},
	} {
		if got := CleanFileName(x[0]); got != x[1] {
			t.Errorf("Expected %q but got %q.", x[1], got)
		}
	}
}

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
