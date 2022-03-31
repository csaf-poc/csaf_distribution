# Create TLS client certificates (for testing)

For testing and development purposes we reuse
the bare bones certificate authority from the
[development-ca.md](development-ca.md).

(In production setups, it is very likely that two different CAs
would used for server and for client certificates.)

The following lines directly create the client certificate.
(As opposed to first creating a certificate signing request and
then signing it.)
<!-- MARKDOWN-AUTO-DOCS:START (CODE:src=../docs/scripts/createCCForITest.sh&lines=17-35) -->
<!-- MARKDOWN-AUTO-DOCS:END -->

and we do a second one with shorter expiration day:

<!-- MARKDOWN-AUTO-DOCS:START (CODE:src=../docs/scripts/createCCForITest.sh&lines=36-54) -->
<!-- MARKDOWN-AUTO-DOCS:END -->

In case of many CAs are used to verify the client certificates these should be included in the list of the allowed CA certificates in the `ssl_client_certificate` bundle of nginx.

E.g. `cat rootca-cert-1.pem rootca-cert-2.pem >> allowedCAs.pem`. Nginx config: `ssl_client_certificate allowedCAs.pem;`
