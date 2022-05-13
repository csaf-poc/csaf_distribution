## csaf_uploader

Following options are supported:

| Options                                    | Description                                                                                |
| ------------------------------------------ | ------------------------------------------------------------------------------------------ |
| -a, --action=[upload\|create]              | Action to perform (default: upload)                                                        |
| -u, --url=URL                              | URL of the CSAF provider (default:https:<span></span>//localhost/cgi-bin/csaf_provider.go) |
| -t, --tlp=[csaf\|white\|green\|amber\|red] | TLP of the feed (default: csaf)                                                            |
| -x, --external-signed                      | CSAF files are signed externally. Assumes .asc files beside CSAF files                     |
| -k, --key=KEY-FILE                         | OpenPGP key to sign the CSAF files                                                         |
| -p, --password=PASSWORD                    | Authentication password for accessing the CSAF provider                                    |
| -P, --passphrase=PASSPHRASE                | Passphrase to unlock the OpenPGP key                                                       |
| -i, --password-interactive                 | Enter password interactively                                                               |
| -I, --passphrase-interacive                | Enter passphrase interactively                                                             |
| -c, --config=INI-FILE                      | Path to config ini file                                                                    |
| --insecure                                 | Do not check TLS certificates from provider                                                |
| --client-cert                              | TLS client certificate file (PEM encoded data)                                             |
| --client-key                               | TLS client private key file (PEM encoded data)                                             |
| --version                                   | Display version of the binary                                                              |
| -h, --help                                 | Show help                                                                                  |

E.g. creating the initial directiories and files

```
./csaf_uploader -a create  -u http://localhost/cgi-bin/csaf_provider.go
```

E.g. uploading a csaf-document

```
./csaf_uploader -a upload -I -t white -u http://localhost/cgi-bin/csaf_provider.go  CSAF-document-1.json
```

which asks to enter password interactively.

csaf_uploader can be started with a config file like following:

```
./csaf_provider -c conf.ini
```

config.ini :

```
action=create
u=http://localhost/cgi-bin/csaf_provider.go
```
