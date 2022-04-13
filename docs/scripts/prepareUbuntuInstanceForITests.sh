#!/usr/bin/env bash
set -e

# This script prepares a naked Ubuntu 20.04 LTS amd64
# for the csaf_distribution integration tests
# by installing the required packages.


apt install -y make bash sed tar git nginx fcgiwrap gnutls-bin

# Install Go from binary distribution
curl -O https://storage.googleapis.com/golang/go1.18.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.18.linux-amd64.tar.gz
