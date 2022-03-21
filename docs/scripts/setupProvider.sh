#!/usr/bin/env bash

# This file is Free Software under the MIT License
# without warranty, see README.md and LICENSES/MIT.txt for details.
#
# SPDX-License-Identifier: MIT
#
# SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

# This script sets up the csaf_provider. It installs nginx, fcgiwrap, git and go if they are not installed.
# It also configures nginx and set the paths.

NGINX_CONFIG_PATH=/etc/nginx/sites-available/default
# Install nginx and fcgiwrap
apt-get install -y nginx fcgiwrap

cp /usr/share/doc/fcgiwrap/examples/nginx.conf /etc/nginx/fcgiwrap.conf

cd /var/www
chgrp -R www-data .
chmod -R g+w .

echo '
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
}
' > /etc/nginx/fcgiwrap.conf

# Configure nginx to use the fcgiwrwrap.conf
if  [ -z  "$(grep "^\s*include fcgiwrap*" $NGINX_CONFIG_PATH)" ]; then
    sed -i "/^server {/a include fcgiwrap.conf;" $NGINX_CONFIG_PATH;
fi
# Reload nginx
systemctl reload nginx

# Install git
apt install -y git
cd ~
# Clone repository
rm -rf csaf_distribution/
git clone https://github.com/csaf-poc/csaf_distribution.git

# Install Go
if [ -z "$(which go)" ]; then
    ./csaf_distribution/docs/scripts/installGo.sh
    # Apply the changes (GOPATH) in ".profile" immediately
    source ~/.profile
fi

cd csaf_distribution
echo "Building csaf_provider binary ...."
go build -o ./ -v ./cmd/csaf_provider/
# Place the binary under the corresponding path.
mkdir -p /usr/lib/cgi-bin/
cp csaf_provider /usr/lib/cgi-bin/csaf_provider.go

mkdir -p /usr/lib/csaf/
# Configuration file
echo '
# upload_signature = true
# key = "/usr/lib/csaf/public.asc"
# key = "/usr/lib/csaf/private.asc"
#tlps = ["green", "red"]
domain = "http://localhost"
#no_passphrase = true
' > /usr/lib/csaf/config.toml

# Create the Folders
curl http://localhost/cgi-bin/csaf_provider.go/create


