// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

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
		{`..`, `_.json`},
		{`../..`, `_.json`},
		{`abc.html`, `abc_html.json`},
		{`abc_.htm__l`, `abc_htm_l.json`},
		{`foo+BAR`, `foo+bar.json`},
	} {
		if got := CleanFileName(x[0]); got != x[1] {
			t.Errorf("%q: Expected %q but got %q.", x[0], x[1], got)
		}
	}
}

func TestConformingFileName(t *testing.T) {
	for _, x := range []struct {
		s string
		b bool
	}{
		{`HELLO`, false},
		{`hello`, false},
		{`cisco-sa-20190513-secureboot.json`, true},
		{`example_company_-_2019-yh3234.json`, true},
		{`rhba-2019_0024.json`, true},
		{`2022__01-a.json`, false},
		{``, false},
		{`..`, false},
		{`../..`, false},
		{`abc.html`, false},
		{`abc_.htm__l`, false},
		{`foo+BAR`, false},
	} {
		if got := ConformingFileName(x.s); got != x.b {
			t.Errorf("%q: Expected %t but got %t.", x.s, x.b, got)
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
