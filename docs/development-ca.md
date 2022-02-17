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


## Considerations and References

 * The command line and template options are explained in the
   GnuTLS documentation at the end of _certtool Invocation_, see the [section of the current stable documentation](https://gnutls.org/manual/html_node/certtool-Invocation.html), but be aware that it maybe newer than
   the version you have installed.
 * Using GnuTLS instead of OpenSSL, because GnuTLS is an implementation
   with a long, good track record. Configuration is also slightly slimmer.
   (Overall it is positive for the security of Open Standards
   like TLS and CMS, that there are several competing compatible
   implementations. Selecting a different implementation here and there helps
   the ecosystem by fostering that competition.)
 * Using the GnuTLS default algorithm (RSA 3072 at time for writing) is
   good enough, as the goal is not to test ECC compatibility for client
   certificates for servers, browser and tools.
 * An example script for server certs:
   https://gist.github.com/epcim/832cec2482a255e3f392
 * An example for client certs as part of the libvirt setup instructions:
   https://wiki.libvirt.org/page/TLSCreateClientCerts
