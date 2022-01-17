# Simple Make file to build csaf_distribution components

SHELL=/bin/bash
BUILD = go build
buildMsg = "Building binaries..."

.PHONY: build build_win build_tag clean

all:
	@echo choose a target from: build build_win build_tag clean

# Build all the binaries and place them in the current directory level.
build:
	@echo $(buildMsg)
	@$(BUILD) -o ./ -v ./cmd/...

# Build the binaries for windows and place them in the current directory level.
build_win:
	@echo $(buildMsg)
	@env GOOS=windows $(BUILD)  -o ./ -v ./cmd/...

# Build the binaries from the latest github tag.
TAG = $(shell git tag --sort=-version:refname | head -n 1)
build_tag:
ifeq ($(TAG),)
	@echo "No Tag found"
else
	@git checkout -q tags/${TAG};
	@echo $(buildMsg)
	@$(BUILD) -o ./ -v ./cmd/...;
	@env GOOS=windows $(BUILD)  -o ./ -v ./cmd/...
	@git checkout -q main
endif

# Remove binary files
clean:
	@rm -f csaf_checker csaf_provider csaf_uploader csaf_checker.exe csaf_provider.exe csaf_uploader.exe


