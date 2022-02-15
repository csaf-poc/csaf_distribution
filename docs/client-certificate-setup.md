# Client-Certificate based authentication

Assuming the userA.pfx file is available, which can be imported into
a web browser.

### Configure nginx
Assuming the relevant server block is in `/etc/nginx/sites-enabled/default`,
adjust it like shown in the following example:

```
server {
    # Other Config
    # ...

    ssl_client_certificate /etc/ssl/rootca-cert.pem;
    ssl_verify_client optional;
    ssl_verify_depth 2;

    # This example allows access to all three TLP locations for all certs.
    location ~ /.well-known/csaf/(red|green|amber)/{
        autoindex on;
        # in this location access is only allowed with client certs
        if  ($ssl_client_verify != SUCCESS){
            # we use status code 404 == "Not Found", because we do not
            # want to reveal if this location exists or not.
            return 404;
        }
    }
}
```
This will restrict the access to the defined paths in the ```location```
directive to only authenticated client certificates issued by the CAs
which are configured with `ssl_client_certificate`.

If you want to restrict each path of `green`, `amber` and `red`
differently, you could use several location blocks
each which a single `if` that matches the `$ssl_client_i_dn` variable
to CAs that you would want to allow for that location.

Reload or restart nginx to apply the changes (e.g. `systemctl reload nginx`
on Debian or Ubuntu.)

To test this see [development-client-certs.md](development-client-certs.md) and
* From the browser after importing the `testclient1.p12`:
nagivate to the protected directories.
* With curl: `curl https://{serverURL}/.well-known/csaf/red/ --cert-type p12 --cert testclient1.crt`

