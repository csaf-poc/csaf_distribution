# Setup provider

The provider is meant to run as an CGI program in an nginx enviroment.

The following instructions are for an Debian 11 server setup.

```(shell)
apt-get install nginx fcgiwrap
cp /usr/share/doc/fcgiwrap/examples/nginx.conf /etc/nginx/fcgiwrap.conf
systemctl status fcgiwrap.service
systemctl status fcgiwrap.socket
systemctl is-enabled fcgiwrap.service
systemctl is-enabled fcgiwrap.socket
```

```(shell)
cd /var/www
chgrp -R www-data .
chmod -R g+w .
```

Content of `/etc/nginx/fcgiwrap.conf`

```
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
```

Add to `/etc/nginx/sites-enabled/default`:

```
server {

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

Place the binary under `/usr/lib/cgi-bin/csaf_provider.go`.
Make sure `/usr/lib/cgi-bin/` exists.

Create configuarion file under `/usr/lib/csaf/config.toml`:

```
# upload_signature = true
# key = "/usr/lib/csaf/public.asc"
key = "/usr/lib/csaf/private.asc"
#tlps = ["green", "red"]
domain = "http://192.168.56.102"
#no_passphrase = true
```
with suitable replacements
(This configurations-example assumes that the private/public keys are available under `/usr/lib/csaf/`).



Create the folders:
```(shell)
curl http://192.168.56.102/cgi-bin/csaf_provider.go/create
```
