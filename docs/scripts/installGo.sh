# This file is Free Software under the MIT License
# without warranty, see README.md and LICENSES/MIT.txt for details.
#
# SPDX-License-Identifier: MIT
#
# SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

# This script installs Go and sets the PATH environment variable.

curl -O https://storage.googleapis.com/golang/go1.18.linux-amd64.tar.gz

tar -C /usr/local -xzf go1.18.linux-amd64.tar.gz

export PATH=$PATH:/usr/local/go/bin

