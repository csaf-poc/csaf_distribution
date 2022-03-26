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
# Usage Example: env FOLDERNAME=devca1 ORGANAME="CSAF Tools Development (internal)" ./serverCA.sh

NGINX_CONFIG_PATH=/etc/nginx/sites-available/default

cd csaf_distribution/docs/scripts/
## Create Root CA
./createRootCA.sh

## Create webserver cert
source ./createWebserverCert.sh

# Cofigure nginx
# Assign the generated CA and key to ssl_certificate and ssl_certificate_key directives.
if grep  "^\s*ssl_certificate .*" $NGINX_CONFIG_PATH; then
    # Update the value of the ssl_certificate if available.
    sed -i "s|^\s*ssl_certificate .*|$SSL_CERTIFICATE|"  $NGINX_CONFIG_PATH;
elif  grep "^\s*# SSL configuration" $NGINX_CONFIG_PATH; then
    # Place the  ssl configuration under # SSL configuration
    sed -i "/^\s*# SSL configuration/a $SSL_CERTIFICATE" $NGINX_CONFIG_PATH;
    else
    sed -i "/^server {/a $SSL_CERTIFICATE"  $NGINX_CONFIG_PATH;
fi

if grep  "^\s*ssl_certificate_key .*" $NGINX_CONFIG_PATH; then
    # Update the value of the ssl_certificate if available.
    sed -i "s|^\s*ssl_certificate_key .*|$SSL_CERTIFICATE_KEY|"  $NGINX_CONFIG_PATH;
elif  grep "^\s*# SSL configuration" $NGINX_CONFIG_PATH; then
    sed -i "/^\s*# SSL configuration/a $SSL_CERTIFICATE_KEY" $NGINX_CONFIG_PATH;
    else
    sed -i "/^server {/a $SSL_CERTIFICATE_KEY"  $NGINX_CONFIG_PATH;
fi
# Enable the ssl parameters of the nginx configurations by commiting them out.
sed -i "/# listen.*443/s/#//" $NGINX_CONFIG_PATH;
# Enable the specified protocols. If condition to avoid duplication.
if  [ -z  "$(grep "^\s*ssl_protocols*" $NGINX_CONFIG_PATH)" ]; then
    sed -i "/^\s*# SSL configuration/a ssl_protocols TLSv1.2 TLSv1.3;" $NGINX_CONFIG_PATH;
fi

# Reload nginx
systemctl reload nginx

