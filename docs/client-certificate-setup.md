# Client-Certificate based authentication

Assuming the userA.pfx file is available, which can be imported into
a web browser.

### Configure nginx
Assuming the relevant server block is in `/etc/nginx/sites-enabled/default`,
adjust it like show in the following example:

```
server {
    # Other Config
    # ...

    ssl_client_certificate /etc/ssl/ca.crt;
    ssl_verify_client optional;
    ssl_verify_depth 2;

    location ~* /.well-known/csaf/(red|green|amber)/{
        autoindex on;a
        if  ($ssl_client_verify != SUCCESS){
            return 403;
        }
    }

}
```
This will restrict the access to the defined paths in the ```location``` directive  to only authenticated client certificates.

Reload or restart nginx to apply the changes (e.g. `systemctl reload nginx`
on Debian or Ubuntu.)

To test this:
* From the browser after importing the ```userA.pfx``` and the navigation to the protected directories.
* With curl: ```curl https://{serverURL}/.well-known/csaf/red/ --cert /etc/ssl/userA.crt --key /etc/ssl/userA.key```.

