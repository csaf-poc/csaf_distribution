# Setup provider

The provider is meant to run as an CGI program in an nginx enviroment.

The following instructions are for an Debian 11 server setup.

```(shell)
apt-get install nginx fcgiwrap
cp /usr/share/doc/fcgiwrap/examples/nginx.conf /etc/nginx/fcgiwrap.conf
```
Check if the CGI server and the fcgiwrap Socket active (running):
```bash
systemctl status fcgiwrap.service
systemctl status fcgiwrap.socket
systemctl is-enabled fcgiwrap.service
systemctl is-enabled fcgiwrap.socket
```
Change the group ownership and the permissions of `/var/www`:
```(shell)
cd /var/www
chgrp -R www-data .
chmod -R g+w .
```

Modify the content of `/etc/nginx/fcgiwrap.conf` like following:

<!-- MARKDOWN-AUTO-DOCS:START (CODE:src=../docs/scripts/setupProviderForITest.sh&lines=24-52) -->
<!-- The below code snippet is automatically added from ../docs/scripts/setupProviderForITest.sh -->
```sh
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
```
<!-- MARKDOWN-AUTO-DOCS:END -->
Add to `/etc/nginx/sites-enabled/default`:

```
server {
    root /var/www/html;

      # Other config
      # ...
    location / {
        # Other config
        # ...

        # For atomic directory switches
        disable_symlinks off;

        # directory listings
        autoindex on;
    }

    # enable CGI

    include fcgiwrap.conf;
}
```
Reload nginx to apply the changes (e.g. ```systemctl reload nginx``` on Debian or Ubuntu).

Create `cgi-bin` folder if not exists `mkdir -p /usr/lib/cgi-bin/`.

Rename and place the `csaf_provider` binary file under `/usr/lib/cgi-bin/csaf_provider.go`.


Create configuration file under `/usr/lib/csaf/config.toml`:

<!-- MARKDOWN-AUTO-DOCS:START (CODE:src=../docs/scripts/setupProviderForITest.sh&lines=82-87) -->
<!-- The below code snippet is automatically added from ../docs/scripts/setupProviderForITest.sh -->
```sh
# upload_signature = true
# key = "/usr/lib/csaf/public.asc"
key = "/usr/lib/csaf/private.asc"
#tlps = ["green", "red"]
canonical_url_prefix = "https://localhost:8443"
#no_passphrase = true
```
<!-- MARKDOWN-AUTO-DOCS:END -->
with suitable [replacements](#provider-options)
(This configuration examples assumes that the private/public keys are available under `/usr/lib/csaf/`).


Create the folders:
```(shell)
curl https://192.168.56.102/cgi-bin/csaf_provider.go/create --cert-type p12 --cert {clientCertificatfile}
```
Replace {clientCertificate} with the client certificate file.
Or using the uploader:
```(shell)
./csaf_uploader -a create -u http://192.168.56.102/cgi-bin/csaf_provider.go -p {password}
```
Replace {password} with the password used for the authentication with csaf_provider.
This needs to set the `password` option in `config.toml`.

## Provider options
Provider has many config options described as following:

 - password: Authentication password for accessing the CSAF provider.
 - key: The private OpenPGP key.
 - folder: Specify the root folder. Default: `/var/www/`.
 - web: Specify the web folder. Default: `/var/www/html`.
 - tlps: Set the allowed TLP comming with the upload request (one or more of "csaf", "white", "amber", "green", "red").
   The "csaf" selection lets the provider takes the value from the CSAF document.
   These affects the list items in the web interface.
   Default: `["csaf", "white", "amber", "green", "red"]`.
 - upload_signature: Send signature with the request, an additional input-field in the web interface will be shown to let user enter an ascii armored signature. Default: `false`.
 - openpgp_url: URL to OpenPGP key-server. Default: `https://openpgp.circl.lu`.
 - canonical_url_prefix: start of the URL where contents shall be accessible from the internet. Default: `https://$SERVER_NAME`.
 - no_passphrase: Let user send password with the request, if set to true the input-field in the web interface will be disappeared. Default: `false`.
 - no_validation: Validate the uploaded CSAF document against the JSON schema. Default: `false`.
 - no_web_ui: Disable the web interface. Default: `false`.
 - dynamic_provider_metadata: Take the publisher from the CSAF document. Default: `false`.
 - provider_metadata: Configure the provider metadata.
 - provider_metadata.list_on_CSAF_aggregators: List on aggregators
 - provider_metadata.mirror_on_CSAF_aggregators: Mirror on aggregators
 - provider_metadata.publisher: Set the publisher. Default: `{"category"= "vendor", "name"= "Example", "namespace"= "https://example.com"}`.
 - upload_limit: Set the upload limit  size of the file. Default: `50 MiB`.
 - issuer: The issuer of the CA, which if set, restricts the writing permission and the accessing to the web-interface to only the client certificates signed with this CA.
