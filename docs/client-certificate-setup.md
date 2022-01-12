## Client-Certificate based authentication

If the certificate Authority and user certificates are already present the steps of creating the certificate authority and client certificates can be skipped.
The following is an example of creating them.

```bash
cd /etc/ssl
```
### Create the Certificate Autority (CA)

Firstly, generate the CA:      
```openssl genrsa -aes256 -out ca.key 4096```          
This asks to enter a passphrase.       
Next, create the server-side certificate, that will be sent via the TLS server to the client.             
```openssl req -new -x509 -days 365 -key ca.key -out ca.crt```       
You will be asked to answer a few questions.

### Create a client certificate

Create the key like previously:              
```openssl genrsa -aes256 -out userA.key 4906```               
Then create a Certificate Signing Request (CSR)                   
```openssl req -new -key userA.key -out userA.csr```                
A number of questions should be answered also.

### Sign the CSRs
A CSR should be signed with the firstly created certificate (CA)                              
```openssl x509 -req -days 365 365 -in userA.csr -CA ca.crt -CAkey ca.key -set_serial01 -out userA.cert```

#### Create a PFX file
For the browser option the signed certificate must be made installable in
a way the public key and the certificate of the client are bundled.                    
```openssl pkcs12 -export -out userA.pfx -inkey userA.key -in user.crt --certfile ca.crt```                
This will ask to provide an export password.      

This generates userA.pfx file, that can be imported into web browser.

### Configure nginx                            
Adjust the server block in ```/etc/nginx/sites-enabled/default```:

```
server {
    # Other Config
    # ...

    ssl_client_certificate /etc/ssl/ca.crt;
    ssl_verify_client optional;
    ssl_verify_depth 2;

    location ~* /.well-known/csaf/(red|green|amber)/{
        autoindex on;a
        if  ($ssl_client_verify != SUCESS){
            retrun 403;
        }
    }

}
```
This will restrict the access to the defined paths in the ```location``` directive  to only authenticated client certificates.

Restart nginx with ```systemctl nginx restart``` to apply the changes.

To test this:
* From the browser after importing the ```userA.pfx``` and the navigation to the protected directories.
* With curl: ```curl https://{serverURL}/.well-known/csaf/red/ --cert /etc/ssl/userA.crt --key /etc/ssl/userA.key```.


