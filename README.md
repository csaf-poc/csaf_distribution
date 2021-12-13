# csaf_distribution

**WIP**: A prove of concept for a CSAF trusted provider, checker and aggregator.


## Setup

- A recent version of **Go** (1.17+) should be installed. [Go installation](https://go.dev/doc/install)

- Clone the repository `git clone https://github.com/csaf-poc/csaf_distribution.git `

- Build Go components
 ``` bash
 cd csaf_distribution
 go build -v ./cmd/...
```

- [Install](http://nginx.org/en/docs/install.html)  **nginx**
- To configure nginx see [docs/provider-setup.md](docs/provider-setup.md)

## csaf_uploader
csaf_uploader is a command line tool that upload CSAF-Documents to the trusted provider (CSAF_Provider).
Follwoing options are supported:

| Options                                    | Description                                                                                |
| ------------------------------------------ | ------------------------------------------------------------------------------------------ |
| -a, --action=[upload\|create]              | Action to perform (default: upload)                                                        |
| -u, --url=URL                              | URL of the CSAF provider (default:https:<span></span>//localhost/cgi-bin/csaf_provider.go) |
| -t, --tlp=[csaf\|white\|green\|amber\|red] | TLP of the feed (default: csaf)                                                            |
| -x, --external-signed                      | CASF files are signed externally.                                                          |
| -k, --key=KEY-FILE                         | OpenPGP key to sign the CSAF files                                                         |
| -p, --password=PASSWORD                    | Authentication password for accessing the CSAF provider                                    |
| -P, --passphrase=PASSPHRASE                | Passphrase to unlock the OpenPGP key                                                       |
| -i, --password-interactive                 | Enter password interactively                                                               |
| -I, --passphrase-interacive                | Enter passphrase interactively                                                             |
| -c, --config=INI-FILE                      | Path to config ini file                                                                    |
| -h, --help                                 | Show help                                                                                  |

E.g. of Creating the initial directiories and files.

```
./csaf_uploader -a create  -u http://localhost/cgi-bin/csaf_provider.go
```

E.g. of Uploading a csaf-document

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


## License

- csaf_distribution is licensed as Free Software under MIT License.

- See the specific source files
for details, the license itself can be found in the directory `LICENSES`.