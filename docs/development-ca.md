# Certificate Authority for development purposes

A bare bones development certificate authority (CA) can be set up
to create certs for serving TLS connections.

Install GnuTLS, E.g. with `apt install gnutls-bin` (3.7.1-5) on Debian Bullseye.

All the private keys will be created without password protection,
which is suitable for testing in development setups.


## create root CA

```bash
mkdir devca1
cd devca1

certtool --generate-privkey --outfile rootca-key.pem

echo '
organization = "CSAF Tools Development (internal)"
country = DE
cn = "Tester"

ca
cert_signing_key
crl_signing_key

serial = 001
expiration_days = 100
' >gnutls-certtool.rootca.template

certtool --generate-self-signed --load-privkey rootca-key.pem --outfile rootca-cert.pem --template gnutls-certtool.rootca.template
```


## create webserver cert

```bash
#being in devca1/

certtool --generate-privkey --outfile testserver-key.pem

echo '
organization = "CSAF Tools Development (internal)"
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

certtool --generate-certificate --load-privkey testserver-key.pem --outfile testserver.crt --load-ca-certificate rootca-cert.pem --load-ca-privkey rootca-key.pem --template gnutls-certtool.testserver.template

cat testserver.crt rootca-cert.pem >bundle.crt
echo Full path config options for nginx:
echo "    ssl_certificate \"$PWD/bundle.crt\";"
echo "    ssl_certificate_key \"$PWD/testserver-key.pem\";"
```
