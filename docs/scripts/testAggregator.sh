#!/usr/bin/env bash

# This file is Free Software under the MIT License
# without warranty, see README.md and LICENSES/MIT.txt for details.
#
# SPDX-License-Identifier: MIT
#
# SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

# The same directory name used in the config-example file.
sudo chgrp -R www-data  /var/csaf_aggregator
sudo chmod -R g+w  /var/csaf_aggregator

cd ~/csaf_distribution/
sudo ./bin-linux-amd64/csaf_aggregator -c docs/examples/aggregator.toml
