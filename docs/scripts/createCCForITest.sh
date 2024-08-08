# This file is Free Software under the Apache-2.0 License
# without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
#
# SPDX-License-Identifier: Apache-2.0
#
# SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

# This scripts creates two client certificates. It uses for signing the root certifcate
# created with `createRootCAForITest.sh` that must be run earlier.

set -e

sudo mkdir -p ~/${FOLDERNAME}
cd ~/${FOLDERNAME}

sudo certtool --generate-privkey --outfile testclient1-key.pem

echo '
organization = "'${ORGANAME}'"
country = DE
cn = "TLS Test Client 1"

tls_www_client
signing_key
encryption_key

serial = 020
expiration_days = 50
'  | sudo tee gnutls-certtool.testclient1.template

sudo certtool --generate-certificate --load-privkey testclient1-key.pem --outfile testclient1.crt --load-ca-certificate rootca-cert.pem --load-ca-privkey rootca-key.pem --template gnutls-certtool.testclient1.template --stdout | head -1

sudo certtool --load-ca-certificate rootca-cert.pem --load-certificate testclient1.crt --load-privkey testclient1-key.pem --to-p12 --p12-name "Test Client 1" --null-password --outder --outfile testclient1.p12

sudo certtool --generate-privkey --outfile testclient2-key.pem

echo '
organization = "'${ORGANAME}'"
country = DE
cn = "TLS Test Client 2"

tls_www_client
signing_key
encryption_key

serial = 021
expiration_days = 1
' | sudo tee gnutls-certtool.testclient2.template

sudo certtool --generate-certificate --load-privkey testclient2-key.pem --outfile testclient2.crt --load-ca-certificate rootca-cert.pem --load-ca-privkey rootca-key.pem --template gnutls-certtool.testclient2.template --stdout | head -1

sudo certtool --load-ca-certificate rootca-cert.pem --load-certificate testclient2.crt --load-privkey testclient2-key.pem --to-p12 --p12-name "Test Client 2" --null-password --outder --outfile testclient2.p12

SSL_CLIENT_CERTIFICATE=$(
echo "$PWD/rootca-cert.pem"
)
