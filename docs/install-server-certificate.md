# Configure TLS Certificate for HTTPS

## Get a webserver TLS certificate

There are three ways to get a TLS certificate for your HTTPS server:
 1. Get it from a certificate provider who will run a certificate
 authority (CA) and also offers
 [extended validation](https://en.wikipedia.org/wiki/Extended_Validation_Certificate) (EV)
 for the certificate. This will cost a fee.
 If possible, create the private key yourself,
 then send a Certificate Signing Request (CSR).
 Overall follow the documentation of the CA operator.
 2. Get a domain validated TLS certificate via
 [Let's encrypt](https://letsencrypt.org/) without a fee.
 See their instruction, e.g.
 [certbot for nignx on Ubuntu](https://certbot.eff.org/instructions?ws=nginx&os=ubuntufocal).
 3. [Run your own little CA](development-ca.md).
 Which has the major drawback that someone
 will have to import the root certificate in the webbrowsers manually or
 override warning on each connect.
 Suitable for development purposes, must not be used for production servers.

To decide between 1. and 2. you will need to weight the extra
efforts and costs of the level of extended validation against
a bit of extra trust for the security advisories
that will be served under the domain.


## Install the files for ngnix

Place the certificates on the server machine.
This includes the certificate for your webserver, the intermediate
certificates and the root certificate. The latter may already be on your
machine as part of the trust anchors for webbrowsers.

Follow the [nginx documentation](https://docs.nginx.com/nginx/admin-guide/security-controls/terminating-ssl-http/)
to further configure TLS with your private key and the certificates.

We recommend to
 * restrict the TLS protocol version and ciphers following a current
 recommendation (e.g. [BSI-TR-02102-2](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-2.html)).


### Example configuration

Assuming the relevant server block is in `/etc/nginx/sites-enabled/default`,
change the `listen` configuration in the `server {}` block and add options so nginx
finds your your private key and the certificate chain.

<!-- MARKDOWN-AUTO-DOCS:START (CODE:src=../docs/scripts/TLSConfigsForITest.sh&lines=31-37) -->
<!-- The below code snippet is automatically added from ../docs/scripts/TLSConfigsForITest.sh -->
```sh
        listen 443 ssl default_server; # ipv4
        listen [::]:443 ssl http2 default_server;  # ipv6

        ssl_certificate  '${SSL_CERTIFICATE}'; # e.g. ssl_certificate /etc/ssl/csaf/bundle.crt
        ssl_certificate_key '${SSL_CERTIFICATE_KEY}'; # e.g. ssl_certificate_key /etc/ssl/csaf/testserver-key.pem;

        ssl_protocols TLSv1.2 TLSv1.3;
```
<!-- MARKDOWN-AUTO-DOCS:END -->

Reload or restart nginx to apply the changes (e.g. `systemctl reload nginx`
on Debian or Ubuntu.)

Technical hints:
 * When allowing or requiring `TLSv1.3` webbrowsers like
Chromium (seen with version 98) may have higher requirements
on the server certificates they allow,
otherwise they do not connect with `ERR_SSL_KEY_USAGE_INCOMPATIBLE`.
