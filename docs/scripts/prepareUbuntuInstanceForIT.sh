#!/usr/bin/env bash

# This script prepares a naked Ubuntu 20.04 LTS instance for the integration test
# by installing the required packages.

apt install -y make git nginx fcgiwrap gnutls-bin

# Install Go
curl -O https://storage.googleapis.com/golang/go1.18.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.18.linux-amd64.tar.gz
