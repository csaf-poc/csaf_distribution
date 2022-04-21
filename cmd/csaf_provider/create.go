// This file is Free Software under the MIT License
// without warranty, see README.md and LICENSES/MIT.txt for details.
//
// SPDX-License-Identifier: MIT
//
// SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2021 Intevation GmbH <https://intevation.de>

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

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
	if _, err := os.Stat(security); err != nil {
		if os.IsNotExist(err) {
			f, err := os.Create(security)
			if err != nil {
				return err
			}
			fmt.Fprintf(
				f, "CSAF: %s/.well-known/csaf/provider-metadata.json\n",
				c.CanonicalURLPrefix)
			return f.Close()
		}
		return err
	}
	return nil
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
