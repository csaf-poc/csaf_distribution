// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/csaf-poc/csaf_distribution/csaf"
	"github.com/csaf-poc/csaf_distribution/util"
)

// ensureFolders initializes the paths and call functions to create
// the directories and files.
func ensureFolders(c *config) error {

	wellknown := filepath.Join(c.Web, ".well-known")
	wellknownCSAF := filepath.Join(wellknown, "csaf")

	if err := createWellknown(wellknownCSAF); err != nil {
		return err
	}

	if err := createFeedFolders(c, wellknownCSAF); err != nil {
		return err
	}

	if err := createProviderMetadata(c, wellknownCSAF); err != nil {
		return err
	}

	return createSecurity(c, wellknown)
}

// createWellknown creates ".well-known" directory if not exist and returns nil.
// An error is returned if the it is not a directory.
func createWellknown(wellknown string) error {
	st, err := os.Stat(wellknown)
	if err != nil {
		if os.IsNotExist(err) {
			return os.MkdirAll(wellknown, 0755)
		}
		return err
	}
	if !st.IsDir() {
		return errors.New(".well-known/csaf is not a directory")
	}
	return nil
}

// createFeedFolders creates the feed folders according to the tlp values
// in the "tlps" config option if they do not already exist.
// No creation for the "csaf" option will be done.
// It creates also symbolic links to feed folders.
func createFeedFolders(c *config, wellknown string) error {
	for _, t := range c.TLPs {
		if t == tlpCSAF {
			continue
		}
		tlpLink := filepath.Join(wellknown, string(t))
		if _, err := filepath.EvalSymlinks(tlpLink); err != nil {
			if os.IsNotExist(err) {
				tlpFolder := filepath.Join(c.Folder, string(t))
				if tlpFolder, err = util.MakeUniqDir(tlpFolder); err != nil {
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

// createSecurity creates the "security.txt" file if does not exist
// and writes the CSAF field inside the file.
func createSecurity(c *config, wellknown string) error {
	security := filepath.Join(wellknown, "security.txt")

	path := fmt.Sprintf(
		"%s/.well-known/csaf/provider-metadata.json",
		c.CanonicalURLPrefix)

	st, err := os.Stat(security)
	if err != nil {
		if os.IsNotExist(err) {
			f, err := os.Create(security)
			if err != nil {
				return err
			}
			fmt.Fprintf(f, "CSAF: %s\n", path)
			return f.Close()
		}
		return err
	}

	// Load it line wise
	found, lines, err := func() (bool, []string, error) {
		f, err := os.Open(security)
		if err != nil {
			return false, nil, err
		}
		defer f.Close()
		var lines []string
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			if s := strings.TrimLeftFunc(line, unicode.IsSpace); strings.HasPrefix(s, "CSAF:") {
				// Check if we are already in.
				if strings.TrimSpace(s[len("CSAF:"):]) == path {
					return true, nil, nil
				}
			}
			lines = append(lines, line)
		}
		return false, lines, sc.Err()
	}()
	if err != nil {
		return err
	}

	// we are already in the file.
	if found {
		return nil
	}

	// Insert our CSAF line at the beginning
	// to get higher priority over possible existing CSAF lines.
	csafLine := fmt.Sprintf("CSAF: %s", path)
	lines = append([]string{csafLine}, lines...)

	// Write back to second file and switch over afterwards.
	newSecurity, nf, err := util.MakeUniqFile(security + ".tmp")
	if err != nil {
		return err
	}

	for _, line := range lines {
		if _, err := fmt.Fprintln(nf, line); err != nil {
			nf.Close()
			os.RemoveAll(newSecurity)
			return err
		}
	}
	if err := nf.Close(); err != nil {
		os.RemoveAll(newSecurity)
		return err
	}

	// Swap atomically.
	if err := os.Rename(newSecurity, security); err != nil {
		os.RemoveAll(newSecurity)
		return err
	}

	// Re-establish old permissions.
	return os.Chmod(security, st.Mode().Perm())
}

// createProviderMetadata creates the provider-metadata.json file if does not exist.
func createProviderMetadata(c *config, wellknownCSAF string) error {
	path := filepath.Join(wellknownCSAF, "provider-metadata.json")
	_, err := os.Stat(path)
	if err == nil {
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	pm := csaf.NewProviderMetadataDomain(c.CanonicalURLPrefix, c.modelTLPs())
	pm.Publisher = c.Publisher

	// Set OpenPGP key.
	key, err := c.loadCryptoKey()
	if err != nil {
		return err
	}
	pm.SetPGP(key.GetFingerprint(), c.GetOpenPGPURL(key))

	return util.WriteToFile(path, pm)
}
