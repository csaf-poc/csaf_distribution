#!/usr/bin/env bash

# This file is Free Software under the MIT License
# without warranty, see README.md and LICENSES/MIT.txt for details.
#
# SPDX-License-Identifier: MIT
#
# SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

set -e  # to exit if a command in the script fails

echo ==== run checker
cd ~/csaf_distribution

./bin-linux-amd64/csaf_checker -o ../checker-results.html --insecure \
--client-cert ~/devca1/testclient1.crt --client-key \
~/devca1/testclient1-key.pem localhost -f html

cat ../checker-results.html
