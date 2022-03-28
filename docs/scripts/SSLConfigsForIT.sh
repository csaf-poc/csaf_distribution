#!/usr/bin/env bash

# This file is Free Software under the MIT License
# without warranty, see README.md and LICENSES/MIT.txt for details.
#
# SPDX-License-Identifier: MIT
#
# SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

# This script generates webserver cert that is signed with the generated root CA.
# It sets the right nginx configurations for serving TLS connections.
# FOLDERNAME and ORGANAME valriables should be set.
# FOLDERNAME: Where to store the CAs and keys.
# ORGANAME: The organization name used in the CA template.
# Usage Example: env FOLDERNAME=devca1 ORGANAME="CSAF Tools Development (internal)" ./SSLConfigsForIT.sh

NGINX_CONFIG_PATH=/etc/nginx/sites-available/default

cd ~/csaf_distribution/docs/scripts/
## Create Root CA
./createRootCAForIT.sh

## Create webserver cert
source ./createWebserverCertForIT.sh

# Cofigure nginx
echo $
echo '
        listen 443 ssl default_server; # ipv4
        listen [::]:443 ssl http2 default_server;  # ipv6

       '${SSL_CERTIFICATE}' # e.g. ssl_certificate devca1/bundle.crt
       '${SSL_CERTIFICATE_KEY}' # e.g. ssl_certificate_key devca1/testserver-key.pem;

        ssl_protocols TLSv1.2 TLSv1.3;

        # Other Config
        # ...
' > SSLConfigs.txt


sed -i "22r ${HOME}/${FOLDERNAME}/SSLConfigs.txt" $NGINX_CONFIG_PATH

# Reload nginx
systemctl reload nginx

