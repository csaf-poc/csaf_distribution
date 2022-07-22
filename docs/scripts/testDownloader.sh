#!/usr/bin/env bash

# This file is Free Software under the MIT License
# without warranty, see README.md and LICENSES/MIT.txt for details.
#
# SPDX-License-Identifier: MIT
#
# SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

set -e  # to exit if a command in the script fails

cd ~/csaf_distribution

echo
echo '==== run downloader (1)'

mkdir ~/downloaded1

./bin-linux-amd64/csaf_downloader --directory ../downloaded1 \
  --rate 4.1 --verbose --insecure localhost

echo
echo '==== this was downloaded (1)'
pushd ~/downloaded1
find .
popd

echo
echo '==== run downloader (2)'

mkdir ~/downloaded2

./bin-linux-amd64/csaf_downloader --directory ../downloaded2 \
  --verbose --insecure https://localhost:9443/.well-known/csaf-aggregator/local-dev-provider2/provider-metadata.json

echo
echo '==== this was downloaded (2)'
pushd ~/downloaded2
find .
popd
