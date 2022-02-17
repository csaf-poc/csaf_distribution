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


# Build binaries and place them under bin-$(GOOS)-$(GOARCH)
# Using 'Target-specific Variable Values' to specify the build target system

GOARCH = amd64
build_linux: GOOS = linux
build_win: GOOS = windows

build_linux build_win:
	$(eval BINDIR = bin-$(GOOS)-$(GOARCH)/ )
	$(MKDIR) $(BINDIR)
	env GOARCH=$(GOARCH) GOOS=$(GOOS) $(BUILD) -o $(BINDIR) -v ./cmd/...


# Remove bin-*-* directories
mostlyclean:
	rm -rf ./bin-*-*
	@echo Files in \`go env GOCACHE\` remain.
