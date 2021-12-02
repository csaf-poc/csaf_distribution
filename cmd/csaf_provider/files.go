package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func deepCopy(dst, src string) error {

	stack := []string{dst, src}

	for len(stack) > 0 {
		src = stack[len(stack)-1]
		dst = stack[len(stack)-2]
		stack = stack[:len(stack)-2]

		if err := func() error {
			dir, err := os.Open(src)
			if err != nil {
				return err
			}
			defer dir.Close()

			// Use Readdir as we need no sorting.
			files, err := dir.Readdir(-1)
			if err != nil {
				return err
			}

			for _, f := range files {
				nsrc := filepath.Join(src, f.Name())
				ndst := filepath.Join(dst, f.Name())
				if f.IsDir() {
					// Create new sub dir
					if err := os.Mkdir(ndst, 0755); err != nil {
						return err
					}
					stack = append(stack, ndst, nsrc)
				} else if f.Mode().IsRegular() {
					// Create hard link.
					if err := os.Link(nsrc, ndst); err != nil {
						return err
					}
				}
			}
			return nil
		}(); err != nil {
			return err
		}
	}

	return nil
}

func mkUniqFile(prefix string) (string, *os.File, error) {
	var file *os.File
	name, err := mkUniq(prefix, func(name string) error {
		var err error
		file, err = os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		return err
	})
	return name, file, err
}

func mkUniqDir(prefix string) (string, error) {
	return mkUniq(prefix, func(name string) error { return os.Mkdir(name, 0755) })
}

func mkUniq(prefix string, create func(string) error) (string, error) {
	now := time.Now()
	stamp := now.Format("-2006-01-02-150405")
	name := prefix + stamp
	err := create(name)
	if err == nil {
		return name, nil
	}
	if os.IsExist(err) {
		rnd := rand.New(rand.NewSource(now.Unix()))

		for i := 0; i < 10000; i++ {
			nname := name + "-" + strconv.FormatUint(uint64(rnd.Uint32()&0xff_ffff), 16)
			err := create(nname)
			if err == nil {
				return nname, nil
			}
			if os.IsExist(err) {
				continue
			}
			return "", err
		}
		return "", &os.PathError{Op: "mkuniq", Path: name, Err: os.ErrExist}
	}

	return "", err
}

func writeHash(fname, name string, h hash.Hash, data []byte) error {

	if _, err := io.Copy(h, bytes.NewReader(data)); err != nil {
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

func saveToFile(fname string, wt io.WriterTo) error {
	f, err1 := os.Create(fname)
	if err1 != nil {
		return err1
	}
	_, err1 = wt.WriteTo(f)
	err2 := f.Close()
	if err1 != nil {
		return err1
	}
	return err2
}
