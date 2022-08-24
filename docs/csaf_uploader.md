## csaf_uploader

### Usage

```
  csaf_uploader [OPTIONS]

Application Options:
  -a, --action=[upload|create]              Action to perform (default: upload)
  -u, --url=URL                             URL of the CSAF provider (default:
                                            https://localhost/cgi-bin/csaf_provider.go)
  -t, --tlp=[csaf|white|green|amber|red]    TLP of the feed (default: csaf)
  -x, --external-signed                     CSAF files are signed externally. Assumes .asc files
                                            beside CSAF files.
  -s, --no-schema-check                     Do not check files against CSAF JSON schema locally.
  -k, --key=KEY-FILE                        OpenPGP key to sign the CSAF files
  -p, --password=PASSWORD                   Authentication password for accessing the CSAF provider
  -P, --passphrase=PASSPHRASE               Passphrase to unlock the OpenPGP key
      --client-cert=CERT-FILE.crt           TLS client certificate file (PEM encoded data)
      --client-key=KEY-FILE.pem             TLS client private key file (PEM encoded data)
  -i, --password-interactive                Enter password interactively
  -I, --passphrase-interactive               Enter passphrase interactively
      --insecure                            Do not check TLS certificates from provider
  -c, --config=INI-FILE                     Path to config ini file
      --version                             Display version of the binary

Help Options:
  -h, --help                                Show this help message
```
E.g. creating the initial directories and files.
This must only be done once, as subsequent `create` calls to the
[csaf_provider](../docs/csaf_provider.md)
may not lead to the desired result.

```bash
./csaf_uploader -a create  -u https://localhost/cgi-bin/csaf_provider.go
```

E.g. uploading a csaf-document

```bash
./csaf_uploader -a upload -I -t white -u https://localhost/cgi-bin/csaf_provider.go  CSAF-document-1.json
```

which asks to enter a password interactively.

By default csaf_uploader will try to load a config file
from the following places:

```
    "~/.config/csaf/uploader.ini",
    "~/.csaf_uploader.ini",
    "csaf_uploader.ini",
```

The command line options can be written in the init file, except:
`password-interactive`, `passphrase-interactive` and `config`.
An example:

```
action=create
u=https://localhost/cgi-bin/csaf_provider.go
```
