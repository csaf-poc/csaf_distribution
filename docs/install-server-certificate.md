# Install TLS Certificate on nginx

If you already have the TLS Certificates you can start with [Link the files](#link-the-files) step.


## Generate a private key and Certificate Signing Request (CSR)
Generate and submit the Certificate Signing Request (CSR) to the issuing Certificate Authority (CA) for processing.

Firstly create the key
```shell
openssl req -new newkey -aes256 -out {domainName}.key 4096
```
Then create the Certificate Singing Request (CSR)

```shell
openssl req -new -key {domainName}.key -out {domainName}.csr
```
A number of questions about the CSR details should be answered.

These generated CSR is necessary for the validation of the TLS certificate generation, thus the content should be submitted to the Certificate Authority to sign the certificate.

## Link the files
Once the CA issues the certificate download it to `/etc/ssl/`.

- If you recieved {domainName}.pem file from the CA when the certificate was issued, then this file contains both primary and intermediate certificate and you can skip the next step.
- Concatenate the primary certificate file ({domainName.crt}) and the intermediate file ({intemediate.crt})
```shell
cat {domainName.crt} {intermediate.crt} >> bundle.crt
```


## Configure nginx
Adjust the server block in ```/etc/nginx/sites-enabled/default```:

```
server {
    listen 443 ssl http2 default_server;
    listen       [::]:443 ssl http2 default_server;

    ssl_certificate /etc/ssl/{domainName.pem}; # or bundle.crt
    ssl_certificate_key /etc/ssl/{domainName}.key";
    # Other Config
    # ...
}

Restart nginx with systemctl nginx restart to apply the changes.