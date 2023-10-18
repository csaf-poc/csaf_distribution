// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/csaf-poc/csaf_distribution/v3/util"
)

type lazyTransaction struct {
	src    string
	dstDir string
	dst    string
}

func newLazyTransaction(src, dstDir string) *lazyTransaction {
	return &lazyTransaction{
		src:    src,
		dstDir: dstDir,
	}
}

func (lt *lazyTransaction) Src() string {
	return lt.src
}

func (lt *lazyTransaction) Dst() (string, error) {
	if lt.dst != "" {
		return lt.dst, nil
	}

	srcBase := filepath.Base(lt.src)

	folder := filepath.Join(lt.dstDir, srcBase)

	dst, err := util.MakeUniqDir(folder)
	if err != nil {
		return "", err
	}

	// Copy old content into new.
	if err := util.DeepCopy(dst, lt.src); err != nil {
		os.RemoveAll(dst)
		return "", err
	}
	lt.dst = dst

	return dst, nil
}

func (lt *lazyTransaction) rollback() error {
	if lt.dst == "" {
		return nil
	}
	err := os.RemoveAll(lt.dst)
	lt.dst = ""
	return err
}

func (lt *lazyTransaction) commit() error {
	if lt.dst == "" {
		return nil
	}
	defer func() { lt.dst = "" }()

	// The expanded path of the original link.
	orig, err := filepath.EvalSymlinks(lt.src)
	if err != nil {
		os.RemoveAll(lt.dst)
		return err
	}

	// Switch directories.
	symlink := filepath.Join(lt.dst, filepath.Base(lt.src))
	if err := os.Symlink(lt.dst, symlink); err != nil {
		os.RemoveAll(lt.dst)
		return err
	}
	log.Printf("Move %q -> %q\n", symlink, lt.src)
	if err := os.Rename(symlink, lt.src); err != nil {
		os.RemoveAll(lt.dst)
		return err
	}

	return os.RemoveAll(orig)
}
