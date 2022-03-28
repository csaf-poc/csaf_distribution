# Certificate Authority for development purposes

A bare bones development certificate authority (CA) can be set up
to create certs for serving TLS connections.

Install GnuTLS, E.g. with `apt install gnutls-bin` (3.7.1-5) on Debian Bullseye.

All the private keys will be created without password protection,
which is suitable for testing in development setups.


## create root CA

<!-- MARKDOWN-AUTO-DOCS:START (CODE:src=../docs/scripts/createRootCAForIT.sh&lines=11-50) -->
<!-- The below code snippet is automatically added from ../docs/scripts/createRootCAForIT.sh -->
```sh
mkdir -p ~/${FOLDERNAME}
cd ~/${FOLDERNAME}

certtool --generate-privkey --outfile rootca-key.pem

echo '
organization = "'${ORGANAME}'"
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
<!-- MARKDOWN-AUTO-DOCS:END -->

## create webserver cert

<!-- MARKDOWN-AUTO-DOCS:START (CODE:src=../docs/scripts/createWebserverCertForIT.sh&lines=11-55) -->
<!-- MARKDOWN-AUTO-DOCS:END -->

Replace `{FOLDERNAME}` with the folder name you want to save the keys into it and `{ORGANAME}` with the organisation name that should be used by creating the Certificate.

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
