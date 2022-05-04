# This file is Free Software under the MIT License
# without warranty, see README.md and LICENSES/MIT.txt for details.
#
# SPDX-License-Identifier: MIT
#
# SPDX-FileCopyrightText: 2021 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2021 Intevation GmbH <https://intevation.de>
#
# Makefile to build csaf_distribution components

SHELL = /bin/bash
BUILD = go build
MKDIR = mkdir -p

.PHONY: build build_linux build_win tag_checked_out mostlyclean

all:
	@echo choose a target from: build build_linux build_win mostlyclean
	@echo prepend \`make BUILDTAG=1\` to checkout the highest git tag before building
	@echo or set BUILDTAG to a specific tag

# Build all binaries
build: build_linux build_win

# if BUILDTAG == 1 set it to the highest git tag
ifeq ($(strip $(BUILDTAG)),1)
override BUILDTAG = $(shell git tag --sort=-version:refname | head -n 1)
endif

ifdef BUILDTAG
# add the git tag checkout to the requirements of our build targets
build_linux build_win: tag_checked_out
endif

tag_checked_out:
	$(if $(strip $(BUILDTAG)),,$(error no git tag found))
	git checkout -q tags/${BUILDTAG}
	@echo Don\'t forget that we are in checked out tag $(BUILDTAG) now.

# use bash shell arithmetic and sed to turn a `git describe` version
# into a semver version. For this we increase the PATCH number, so that
# any commit after a tag is considered newer than the semver from the tag
# without an optional 'v'
GITDESC := $(shell git describe)
GITDESCPATCH := $(shell echo '$(GITDESC)' | sed -E 's/v?[0-9]+\.[0-9]+\.([0-9]+)[-+]?.*/\1/')
SEMVERPATCH := $(shell echo $$(( $(GITDESCPATCH) + 1 )))
# Hint: The regexp in the next line only matches if there is a hyphen (`-`)
#       and we can assume that git describe has added a string after the tag
SEMVER := $(shell echo '$(GITDESC)' | sed -E 's/v?([0-9]+\.[0-9]+\.)([0-9]+)(-.*)/\1$(SEMVERPATCH)\3/' )
testsemver:
	@echo from \'$(GITDESC)\' transformed to \'$(SEMVER)\'


# Set -ldflags parameter to pass the semversion.
LDFLAGS = -ldflags "-X github.com/csaf-poc/csaf_distribution/util.SemVersion=$(SEMVER)"

# Build binaries and place them under bin-$(GOOS)-$(GOARCH)
# Using 'Target-specific Variable Values' to specify the build target system

GOARCH = amd64
build_linux: GOOS = linux
build_win: GOOS = windows

build_linux build_win:
	$(eval BINDIR = bin-$(GOOS)-$(GOARCH)/ )
	$(MKDIR) $(BINDIR)
	env GOARCH=$(GOARCH) GOOS=$(GOOS) $(BUILD) -o $(BINDIR) $(LDFLAGS) -v ./cmd/...


DISTDIR := csaf_distribution-$(SEMVER)
dist: build_linux build_win
	mkdir -p dist
	mkdir dist/$(DISTDIR)-windows-amd64
	cp -r README.md docs bin-windows-amd64 dist/$(DISTDIR)-windows-amd64
	mkdir dist/$(DISTDIR)-gnulinux-amd64
	cp -r README.md docs bin-linux-amd64 dist/$(DISTDIR)-gnulinux-amd64
	cd dist/ ; zip -r $(DISTDIR)-windows-amd64.zip $(DISTDIR)-windows-amd64/
	cd dist/ ; tar -cvmlzf $(DISTDIR)-gnulinux-amd64.tar.gz $(DISTDIR)-gnulinux-amd64/

# Remove bin-*-* and dist directories
mostlyclean:
	rm -rf ./bin-*-* dist/
	@echo Files in \`go env GOCACHE\` remain.
