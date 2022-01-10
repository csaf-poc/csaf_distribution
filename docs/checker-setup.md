# Setup checker

To set up the development environment properly (nginx and thus the csaf-provider on the same machine) the following should be done:

## Use domain from the dev-machine

 Edit the `/etc/hosts` file to have another hostname beside the localhost
 ```
 127.0.0.1 localhost testcsaf.com
 ```
## Configure nginx to use self-signed certificate

1.  Generate a self-signed certificate using OpenSSL
    ```bash
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/nginx-selfsigned.key -out /etc/ssl/certs/nginx-selfsigned.crt
    ```
    you will be asked to answer a few question about the server.
    The `Common Name (e.g. server FQDN or YOUR name)` should match the specified server name.
    This generates a key file and certificate in `/etc/ssl`

2.  Configure nginx to use these files

    Create the following nginx configuration snippet files:
    `/etc/nginx/snippets/self-signed.conf` with the content:

    ```bash
     ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
     ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
    ```
    and `/etc/nginx/snippets/ssl-params.conf` with the content:
    ```
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers EECDH+AESGCM:EDH+AESGCM;
    ssl_ecdh_curve secp384r1;
    ssl_session_timeout 10m;
    ssl_session_cache shared:SSL:10m;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    ```
    Adjust the server block `/etc/nginx/sites-enabled/default`:
    ```
    server {
        # Other config
        #....
        listen 443 ssl http2 default_server;
        listen [::]:443 ssl http2 default_server;
        root /var/www/html;
        include snippets/self-signed.conf;
        include snippets/ssl-params.conf;
    }
    ```
Then restart nginx `systemctl restart nginx`

Usage example with these configurations:
``` ./csaf_checker testcsaf.com -f html --insecure > check.html```


