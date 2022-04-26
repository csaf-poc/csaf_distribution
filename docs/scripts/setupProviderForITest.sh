#!/usr/bin/env bash

# This file is Free Software under the MIT License
# without warranty, see README.md and LICENSES/MIT.txt for details.
#
# SPDX-License-Identifier: MIT
#
# SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

# This script sets up the csaf_provider and writes the required nginx configurations.
# It creates the initial folders and uploads some example files to the csaf_provider with the help of `uploadToProvider.sh`

set -e

chgrp -R www-data  /var/www
chmod -R g+w  /var/www

NGINX_CONFIG_PATH=/etc/nginx/sites-available/default

sudo cp /usr/share/doc/fcgiwrap/examples/nginx.conf /etc/nginx/fcgiwrap.conf

sudo echo '
# Include this file on your nginx.conf to support debian cgi-bin scripts using
# fcgiwrap
location /cgi-bin/ {
  # Disable gzip (it makes scripts feel slower since they have to complete
  # before getting gzipped)
  gzip off;

  # Set the root to /usr/lib (inside this location this means that we are
  # giving access to the files under /usr/lib/cgi-bin)
  root  /usr/lib;

  # Fastcgi socket
  fastcgi_pass  unix:/var/run/fcgiwrap.socket;

  # Fastcgi parameters, include the standard ones
  include /etc/nginx/fastcgi_params;

  fastcgi_split_path_info ^(.+\.go)(.*)$;

  # Adjust non standard parameters (SCRIPT_FILENAME)
  fastcgi_param SCRIPT_FILENAME  /usr/lib$fastcgi_script_name;

  fastcgi_param PATH_INFO $fastcgi_path_info;
  fastcgi_param CSAF_CONFIG /usr/lib/csaf/config.toml;

  fastcgi_param SSL_CLIENT_VERIFY $ssl_client_verify;
  fastcgi_param SSL_CLIENT_S_DN $ssl_client_s_dn;
  fastcgi_param SSL_CLIENT_I_DN $ssl_client_i_dn;
}
' > /etc/nginx/fcgiwrap.conf

sudo sed -i "/^server {/a        include fcgiwrap.conf;" $NGINX_CONFIG_PATH

echo "
        # For atomic directory switches
        disable_symlinks off;

        # directory listings
        autoindex on;
" > locationConfig.txt
sudo sed -i "/^\s*location \/ {/r locationConfig.txt" $NGINX_CONFIG_PATH # Insert config inside location{}

sudo systemctl reload nginx

# assuming that we are in a checked out version in the docs/scripts directory
# and we want to build the version that is currently checked out
pushd ../..

export PATH=$PATH:/usr/local/go/bin
make build_linux
# Place the binary under the corresponding path.
sudo mkdir -p /usr/lib/cgi-bin/
sudo cp bin-linux-amd64/csaf_provider /usr/lib/cgi-bin/csaf_provider.go

sudo mkdir -p /usr/lib/csaf/
sudo cp docs/test-keys/*.asc /usr/lib/csaf/
# Configuration file
echo '
# upload_signature = true
# key = "/usr/lib/csaf/public.asc"
key = "/usr/lib/csaf/private.asc"
#tlps = ["green", "red"]
canonical_url_prefix = "https://localhost:8443"
#no_passphrase = true
' > /usr/lib/csaf/config.toml

# Create the Folders
curl https://localhost:8443/cgi-bin/csaf_provider.go/create --cert-type p12 --cert ~/devca1/testclient1.p12 --insecure

popd

# Upload files
./uploadToProvider.sh
