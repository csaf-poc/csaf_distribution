# Simple Make file to build csaf_distribution components

SHELL=/bin/bash
BUILD = go build
MKDIR = mkdir -p bin

.PHONY: build build_win build_tag clean

all:
	@echo choose a target from: build build_linux build_win build_tag clean

# Build the binaries for GNU/linux and place them under bin/ directory.
build_linux:
	@$(MKDIR)
	@echo "Bulding binaries for GNU/Linux ..."
	@$(BUILD) -o ./bin/ -v ./cmd/...

# Build the binaries for windows (cross build) and place them under bin/ directory.
build_win:
	@$(MKDIR)
	@echo "Bulding binaries for windows (cross build) ..."
	@env GOARCH=amd64 GOOS=windows $(BUILD)  -o ./bin/ -v ./cmd/...

# Build the binaries for both GNU/linux and Windows and place them under bin/ directory.
build: build_linux build_win

# Build the binaries from the latest github tag.
TAG = $(shell git tag --sort=-version:refname | head -n 1)
build_tag:
ifeq ($(TAG),)
	@echo "No Tag found"
else
	@git checkout -q tags/${TAG};
	@echo $(buildMsg)
	@$(BUILD) -o ./bin/ -v ./cmd/...;
	@env GOOS=windows $(BUILD)  -o ./ -v ./cmd/...
	@git checkout -q main
endif

# Remove bin/ directory
clean:
	@rm -rf bin/


