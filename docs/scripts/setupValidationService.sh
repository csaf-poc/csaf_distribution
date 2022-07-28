#!/usr/bin/env bash
#
# This file is Free Software under the MIT License
# without warranty, see README.md and LICENSES/MIT.txt for details.
#
# SPDX-License-Identifier: MIT
#
# SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

set -e  # to exit if a command in the script fails

sudo mkdir -p /var/lib/csaf
sudo chgrp www-data /var/lib/csaf/
sudo chmod g+s /var/lib/csaf/
sudo touch /var/lib/csaf/validations.db
sudo chgrp www-data /var/lib/csaf/validations.db
sudo chmod g+rw,o-rwx /var/lib/csaf/validations.db

echo '
remote_validator= { "url" = "http://localhost:8082", "presets" = ["mandatory"], "cache" = "/var/lib/csaf/validations.db" }
' | sudo tee --append /etc/csaf/config.toml

# Install nodejs
curl -fsSL https://deb.nodesource.com/setup_14.x | sudo -E bash -
sudo apt-get install -y nodejs

npm install pm2 -g

pushd ~
git clone https://github.com/secvisogram/csaf-validator-service.git
cd csaf-validator-service
npm ci
pm2 start npm -- run dev
popd
