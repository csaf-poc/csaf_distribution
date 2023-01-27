#!/usr/bin/env bash
set -e

# This script prepares a naked Ubuntu 20.04 LTS amd64
# for the csaf_distribution integration tests
# by installing the required packages.


apt install -y make bash sed tar git nginx fcgiwrap gnutls-bin

# Install Go from binary distribution
latest_go="$(curl https://go.dev/VERSION\?m=text).linux-amd64.tar.gz"
curl -O https://dl.google.com/go/$latest_go
rm -rf /usr/local/go # be sure that we do not have an old installation
tar -C /usr/local -xzf $latest_go
