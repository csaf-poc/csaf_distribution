# Client-Certificate based authentication

Assuming the userA.pfx file is available, which can be imported into
a web browser.

### Configure nginx
Assuming the relevant server block is in `/etc/nginx/sites-enabled/default` and the CA used to verify the client certificates is under `/etc/ssl/`,
adjust the content of the `server{}` block like shown in the following example:
<!-- MARKDOWN-AUTO-DOCS:START (CODE:src=../docs/scripts/TLSClientConfigsForITest.sh&lines=25-38) -->
<!-- The below code snippet is automatically added from ../docs/scripts/TLSClientConfigsForITest.sh -->
```sh
        ssl_client_certificate '${SSL_CLIENT_CERTIFICATE}'; # e.g. ssl_client_certificate /etc/ssl/rootca-cert.pem;
        ssl_verify_client optional;
        ssl_verify_depth 2;

        # This example allows access to all three TLP locations for all certs.
        location ~ /.well-known/csaf/(red|green|amber)/{
            # For atomic directory switches
            disable_symlinks off;
            autoindex on;
            # in this location access is only allowed with client certs
            if  ($ssl_client_verify != SUCCESS){
                return 403;
            }
       }
```
<!-- MARKDOWN-AUTO-DOCS:END -->

This will restrict the access to the defined paths in the ```location```
directive to only authenticated client certificates issued by the CAs
which are configured with `ssl_client_certificate`.

If you want to restrict each path of `green`, `amber` and `red`
differently, you could use several location blocks
each which a single `if` that matches the `$ssl_client_i_dn` variable
to CAs that you would want to allow for that location.

If you want to restrict the writing permission and access to the web-interface
of the `csaf_provider` to only some TLS client certificates,
the CA issuer of these certificates should be assigned to the `issuer`
config option in the `/user/lib/csaf/config.toml` file
e.g. `issuer = "C=DE,O=CSAF Tools Development (internal),CN=Tester" `.
The value will be checked against the `$ssl_client_i_dn` variable
within the `csaf_provider`.
To inspect the precise string of certain certificate, try it and
check the logged value in the nginx log file, e.g. `/var/log/nginx/error.log`.

The *used personal client certificate will be logged by default*,
when accessing the csaf_provider uploading interface.
It is written to the nginx error log together with the connection information.
This is for auditing who did uploads.

Reload or restart nginx to apply the changes (e.g. `systemctl reload nginx`
on Debian or Ubuntu.)

To test this see [development-client-certs.md](development-client-certs.md) and
* From the browser after importing the `testclient1.p12`:
nagivate to the protected directories.
* With curl: `curl https://{serverURL}/.well-known/csaf/red/ --cert-type p12 --cert testclient1.p12`.
(If the server uses a root certifcate that is not in the default certificate store one of the following options should be added to the `curl` command:
    * `--insecure` to disable the verification,
    * `--cacert {CA-Certificate-File}` to pass the CA-Certificate that verifies the server).
