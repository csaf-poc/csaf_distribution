# Create TLS client certificates (for testing)

For testing and development purposes we reuse
the bare bones certificate authority from the
[development-ca.md](development-ca.md).

(In production setups, it is very likely that two different CAs
would used for server and for client certificates.)

The following lines directly create the client certificate.
(As opposed to first creating a certificate signing request and
then signing it.)
<!-- MARKDOWN-AUTO-DOCS:START (CODE:src=../docs/scripts/createCCForITest.sh&lines=15-35) -->
<!-- The below code snippet is automatically added from ../docs/scripts/createCCForITest.sh -->
```sh
cd ~/${FOLDERNAME}

certtool --generate-privkey --outfile testclient1-key.pem

echo '
organization = "'${ORGANAME}'"
country = DE
cn = "TLS Test Client 1"

tls_www_client
signing_key
encryption_key

serial = 020
expiration_days = 50
' > gnutls-certtool.testclient1.template

certtool --generate-certificate --load-privkey testclient1-key.pem --outfile testclient1.crt --load-ca-certificate rootca-cert.pem --load-ca-privkey rootca-key.pem --template gnutls-certtool.testclient1.template --stdout | head -1

certtool --load-ca-certificate rootca-cert.pem --load-certificate testclient1.crt --load-privkey testclient1-key.pem --to-p12 --p12-name "Test Client 1" --null-password --outder --outfile testclient1.p12
```
<!-- MARKDOWN-AUTO-DOCS:END -->

and we do a second one with shorter expiration day:

<!-- MARKDOWN-AUTO-DOCS:START (CODE:src=../docs/scripts/createCCForITest.sh&lines=34-53) -->
<!-- The below code snippet is automatically added from ../docs/scripts/createCCForITest.sh -->
```sh
certtool --load-ca-certificate rootca-cert.pem --load-certificate testclient1.crt --load-privkey testclient1-key.pem --to-p12 --p12-name "Test Client 1" --null-password --outder --outfile testclient1.p12

certtool --generate-privkey --outfile testclient2-key.pem

echo '
organization = "'${ORGANAME}'"
country = DE
cn = "TLS Test Client 2"

tls_www_client
signing_key
encryption_key

serial = 021
expiration_days = 1
' > gnutls-certtool.testclient2.template

certtool --generate-certificate --load-privkey testclient2-key.pem --outfile testclient2.crt --load-ca-certificate rootca-cert.pem --load-ca-privkey rootca-key.pem --template gnutls-certtool.testclient2.template --stdout | head -1

certtool --load-ca-certificate rootca-cert.pem --load-certificate testclient2.crt --load-privkey testclient2-key.pem --to-p12 --p12-name "Test Client 2" --null-password --outder --outfile testclient2.p12
```
<!-- MARKDOWN-AUTO-DOCS:END -->

In case of many CAs are used to verify the client certificates these should be included in the list of the allowed CA certificates in the `ssl_client_certificate` bundle of nginx.

E.g. `cat rootca-cert-1.pem rootca-cert-2.pem >> allowedCAs.pem`. Nginx config: `ssl_client_certificate allowedCAs.pem;`
