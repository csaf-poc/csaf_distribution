#!/usr/bin/env bash
set -e

# This script prepares a naked Ubuntu 20.04 LTS amd64
# for the csaf_distribution integration tests
# by installing the required packages.

apt update
apt install -y make bash curl gnupg sed tar git nginx fcgiwrap gnutls-bin

# Install Go from binary distribution
latest_go="$(curl https://go.dev/VERSION\?m=text).linux-amd64.tar.gz"
curl -O https://dl.google.com/go/$latest_go
rm -rf /usr/local/go # be sure that we do not have an old installation
tar -C /usr/local -xzf $latest_go

# Install newer Node.js version from nodesource
# as needed for https://github.com/secvisogram/csaf-validator-service
# Instructions from
#  https://github.com/nodesource/distributions/blob/master/README.md#debmanual
KEYRING=/usr/share/keyrings/nodesource.gpg
curl -fsSL https://deb.nodesource.com/gpgkey/nodesource.gpg.key | gpg --dearmor > "$KEYRING"
gpg --no-default-keyring --keyring "$KEYRING" --list-keys
chmod a+r /usr/share/keyrings/nodesource.gpg

VERSION=node_16.x
DISTRO="$(lsb_release -s -c)"
echo "deb [signed-by=$KEYRING] https://deb.nodesource.com/$VERSION $DISTRO main" | tee /etc/apt/sources.list.d/nodesource.list
echo "deb-src [signed-by=$KEYRING] https://deb.nodesource.com/$VERSION $DISTRO main" | tee -a /etc/apt/sources.list.d/nodesource.list

apt-get update
apt-get install -y nodejs
