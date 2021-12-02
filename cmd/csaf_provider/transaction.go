package main

import (
	"os"
	"path/filepath"

	"github.com/csaf-poc/csaf_distribution/csaf"
)

func doTransaction(
	cfg *config,
	t tlp,
	fn func(string, *csaf.ProviderMetadata) error,
) error {

	wellknown := filepath.Join(cfg.Web, ".well-known", "csaf")

	metadata := filepath.Join(wellknown, "provider-metadata.json")

	pmd, err := func() (*csaf.ProviderMetadata, error) {
		f, err := os.Open(metadata)
		if err != nil {
			if os.IsNotExist(err) {
				return csaf.NewProviderMetadataDomain(cfg.Domain, cfg.modelTLPs()), nil
			}
			return nil, err
		}
		defer f.Close()
		return csaf.LoadProviderMetadata(f)
	}()

	if err != nil {
		return err
	}

	webTLP := filepath.Join(wellknown, string(t))

	oldDir, err := filepath.EvalSymlinks(webTLP)
	if err != nil {
		return err
	}

	folderTLP := filepath.Join(cfg.Folder, string(t))

	newDir, err := mkUniqDir(folderTLP)
	if err != nil {
		return err
	}

	// Copy old content into new.
	if err := deepCopy(newDir, oldDir); err != nil {
		os.RemoveAll(newDir)
		return err
	}

	// Work with new folder.
	if err := fn(newDir, pmd); err != nil {
		os.RemoveAll(newDir)
		return err
	}

	// Write back provider metadata if its dynamic.
	if cfg.DynamicProviderMetaData {
		newMetaName, newMetaFile, err := mkUniqFile(metadata)
		if err != nil {
			os.RemoveAll(newDir)
			return err
		}

		if _, err := pmd.WriteTo(newMetaFile); err != nil {
			newMetaFile.Close()
			os.Remove(newMetaName)
			os.RemoveAll(newDir)
			return err
		}

		if err := newMetaFile.Close(); err != nil {
			os.Remove(newMetaName)
			os.RemoveAll(newDir)
			return err
		}

		if err := os.Rename(newMetaName, metadata); err != nil {
			os.RemoveAll(newDir)
			return err
		}
	}

	// Switch directories.
	symlink := filepath.Join(newDir, string(t))
	if err := os.Symlink(newDir, symlink); err != nil {
		os.RemoveAll(newDir)
		return err
	}
	if err := os.Rename(symlink, webTLP); err != nil {
		os.RemoveAll(newDir)
		return err
	}

	return os.RemoveAll(oldDir)
}
