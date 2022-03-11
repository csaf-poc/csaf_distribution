#!/usr/bin/env bash

# This file is Free Software under the MIT License
# without warranty, see README.md and LICENSES/MIT.txt for details.
#
# SPDX-License-Identifier: MIT
#
# SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

# This Script generates webserver cert that is signed with the generated root CA.
# It sets the right nginx configurations for serving TLS connections.
# FOLDERNAME and ORGANAME valriables should be set.
# FOLDERNAME: Where to store the CAs and keys.
# ORGANAME: The organization name used in the CA template.
# Usage Example: env FOLDERNAME=devca1 ORGANAME=CSAF Tools Development (internal) ./serverCA.sh

NGINX_Config=/etc/nginx/sites-available/default
# Install gnutls
echo "Install gnutls "
apt install gnutls-bin

## Create Root CA
mkdir -p ~/${FOLDERNAME}
cd ~/${FOLDERNAME}
echo "Generate Root key"
certtool --generate-privkey --outfile rootca-key.pem

echo '
organization = "'${ORGANAME}'"
country = DE
cn = "Tester"

ca
cert_signing_key
crl_signing_key

serial = 001
expiration_days = 100
' >gnutls-certtool.rootca.template

echo "Generate Root CA"
certtool --generate-self-signed --load-privkey rootca-key.pem --outfile rootca-cert.pem --template gnutls-certtool.rootca.template

## Create webserver cert
cd ~/${FOLDERNAME}
echo "Generate testserver key"
certtool --generate-privkey --outfile testserver-key.pem

echo '
organization = "'${ORGANAME}'"
country = DE
cn = "Service Testing"

tls_www_server
signing_key
encryption_key
non_repudiation

dns_name = "*.local"
dns_name = "localhost"

serial = 010
expiration_days = 50
' > gnutls-certtool.testserver.template

echo "Generate testserver CA"
certtool --generate-certificate --load-privkey testserver-key.pem --outfile testserver.crt --load-ca-certificate rootca-cert.pem --load-ca-privkey rootca-key.pem --template gnutls-certtool.testserver.template

cat testserver.crt rootca-cert.pem >bundle.crt

SSL_CERTIFICATE=$(echo "        ssl_certificate \"$PWD/bundle.crt\";")
SSL_CERTIFICATE_KEY=$(echo "        ssl_certificate_key \"$PWD/testserver-key.pem\";")

# Cofigure nginx
# Assign the generated CA and key to ssl_certificate and ssl_certificate_key directives.
if grep  "^\s*ssl_certificate .*" $NGINX_Config; then
    # Update the value of the ssl_certificate if available.
    sed -i "s|^\s*ssl_certificate .*|$SSL_CERTIFICATE|"  $NGINX_Config;
elif  grep "^\s*# SSL configuration" $NGINX_Config; then
    # Place the  ssl configuration under # SSL configuration
    sed -i "/^\s*# SSL configuration/a $SSL_CERTIFICATE" $NGINX_Config;
    else
    sed -i "/^server {/a $SSL_CERTIFICATE"  $NGINX_Config;
fi

if grep  "^\s*ssl_certificate_key .*" $NGINX_Config; then
    # Update the value of the ssl_certificate if available.
    sed -i "s|^\s*ssl_certificate_key .*|$SSL_CERTIFICATE_KEY|"  $NGINX_Config;
elif  grep "^\s*# SSL configuration" $NGINX_Config; then
    sed -i "/^\s*# SSL configuration/a $SSL_CERTIFICATE_KEY" $NGINX_Config;
    else
    sed -i "/^server {/a $SSL_CERTIFICATE_KEY"  $NGINX_Config;
fi
# Enable the ssl parameters of the nginx configurations by commiting them out.
sed -i "/# listen.*443/s/#//" $NGINX_Config;
# Enable the specified protocols. If condition to avoid duplication.
if  [ -z  "$(grep "ssl_protocols*" $NGINX_Config)" ]  ; then
    sed -i "/^\s*# SSL configuration/a ssl_protocols TLSv1.2 TLSv1.3;" $NGINX_Config;
fi

