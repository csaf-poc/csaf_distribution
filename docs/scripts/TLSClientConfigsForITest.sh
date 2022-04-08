#!/usr/bin/env bash

# This file is Free Software under the MIT License
# without warranty, see README.md and LICENSES/MIT.txt for details.
#
# SPDX-License-Identifier: MIT
#
# SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

# It sets the right nginx configurations for enabling client certificate authentication.
# FOLDERNAME and ORGANAME variables must be set.
# FOLDERNAME: Where to store the CAs and keys.
# ORGANAME: The organization name used in the CA template.
# Usage Example: env FOLDERNAME=devca1 ORGANAME="CSAF Tools Development (internal)" ./TLSClientConfigsForITest.sh

set -e

NGINX_CONFIG_PATH=/etc/nginx/sites-available/default

cd ~/csaf_distribution/docs/scripts/
source ./createCCForITest.sh

echo '
        ssl_client_certificate '${SSL_CLIENT_CERTIFICATE}' # e.g. ssl_client_certificate /etc/ssl/rootca-cert.pem;
        ssl_verify_client optional;
        ssl_verify_depth 2;

        # This example allows access to all three TLP locations for all certs.
        location ~ /.well-known/csaf/(red|green|amber)/{

            autoindex on;

            # in this location access is only allowed with client certs
            if  ($ssl_client_verify != SUCCESS){
                # we use status code 404 == "Not Found", because we do not
                # want to reveal if this location exists or not.
                return 404;
            }
       }
'> clientCertificateConfigs.txt

sed -i "/^server {/r  ${HOME}/${FOLDERNAME}/clientCertificateConfigs.txt" $NGINX_CONFIG_PATH

systemctl reload nginx
