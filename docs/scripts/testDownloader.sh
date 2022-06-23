#!/usr/bin/env bash

# This file is Free Software under the MIT License
# without warranty, see README.md and LICENSES/MIT.txt for details.
#
# SPDX-License-Identifier: MIT
#
# SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

set -e  # to exit if a command in the script fails

echo
echo '==== run downloader'
cd ~/csaf_distribution

mkdir ~/downloaded1

./bin-linux-amd64/csaf_downloader --directory ../downloaded1 \
  --rate 4.1 --verbose --insecure localhost

echo
echo '==== this was downloaded'
cd ~/downloaded1
find .
