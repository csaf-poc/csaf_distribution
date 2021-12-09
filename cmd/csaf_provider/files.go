package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io/ioutil"
	"os"
)

func writeHash(fname, name string, h hash.Hash, data []byte) error {

	if _, err := h.Write(data); err != nil {
		return err
	}

	f, err := os.Create(fname)
	if err != nil {
		return err
	}
	fmt.Fprintf(f, "%x %s\n", h.Sum(nil), name)
	return f.Close()
}

func writeHashedFile(fname, name string, data []byte, armored string) error {
	// Write the file itself.
	if err := ioutil.WriteFile(fname, data, 0644); err != nil {
		return err
	}
	// Write SHA256 sum.
	if err := writeHash(fname+".sha256", name, sha256.New(), data); err != nil {
		return err
	}
	// Write SHA512 sum.
	if err := writeHash(fname+".sha512", name, sha512.New(), data); err != nil {
		return err
	}
	// Write signature.
	if err := ioutil.WriteFile(fname+".asc", []byte(armored), 0644); err != nil {
		return err
	}
	return nil
}
