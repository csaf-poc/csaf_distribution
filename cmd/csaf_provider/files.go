package main

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func ensureFolders(c *config) error {

	wellknown, err := createWellknown(c)
	if err != nil {
		return err
	}

	if err := createFeedFolders(c, wellknown); err != nil {
		return err
	}

	return createSecurity(c)
}

func createSecurity(c *config) error {
	security := filepath.Join(c.Web, "security.txt")
	if _, err := os.Stat(security); err != nil {
		if os.IsNotExist(err) {
			f, err := os.Create(security)
			if err != nil {
				return err
			}
			fmt.Fprintf(
				f, "CSAF: https://%s/.wellknown/csaf/provider-metadata.json\n",
				c.Domain)
			return f.Close()
		} else {
			return err
		}
	}
	return nil
}

func createFeedFolders(c *config, wellknown string) error {
	for _, t := range c.TLPs {
		if t == tlpCSAF {
			continue
		}
		tlpLink := filepath.Join(wellknown, string(t))
		if _, err := filepath.EvalSymlinks(tlpLink); err != nil {
			if os.IsNotExist(err) {
				tlpFolder := filepath.Join(c.Folder, string(t))
				if tlpFolder, err = mkUniqDir(tlpFolder); err != nil {
					return err
				}
				if err = os.Symlink(tlpFolder, tlpLink); err != nil {
					return err
				}
			} else {
				return err
			}
		}
	}
	return nil
}

func createWellknown(c *config) (string, error) {
	wellknown := filepath.Join(c.Web, ".well-known", "csaf")

	st, err := os.Stat(wellknown)
	if err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(wellknown, 0755); err != nil {
				return "", err
			}
		} else {
			return "", err
		}
	} else {
		if !st.IsDir() {
			return "", errors.New(".well-known/csaf is not a directory")
		}
	}
	return wellknown, nil
}

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
