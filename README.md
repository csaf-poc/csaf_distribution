# csaf_distribution

**WIP**: A proof of concept for a CSAF trusted provider, checker and aggregator.

## Setup

- A recent version of **Go** (1.17+) should be installed. [Go installation](https://go.dev/doc/install)

- Clone the repository `git clone https://github.com/csaf-poc/csaf_distribution.git `

- Build Go components Makefile supplies the following targets:
	- Build For GNU/Linux System: `make build_linux`
	- Build For Windows System (cross build): `make build_win`
    - Build For both linux and windows: `make build`
	- Build from a specific github tag by passing the intended tag to the `BUILDTAG` variable.
	   E.g. `make BUILDTAG=v1.0.0 build` or `make BUILDTAG=1 build_linux`.
     The special value `1` means checking out the highest github tag for the build.
    - Remove the generated binaries und their directories: `make mostlyclean`

Binaries will be placed in directories named like `bin-linux-amd64/` and `bin-windows-amd64/`.

- [Install](https://nginx.org/en/docs/install.html)  **nginx**
- To install server certificate on nginx see [docs/install-server-certificate.md](docs/install-server-certificate.md)
- To configure nginx see [docs/provider-setup.md](docs/provider-setup.md)

## csaf_uploader

csaf_uploader is a command line tool that uploads CSAF documents to the trusted provider (CSAF_Provider).
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
| --insecure                                 | Do not check TSL certificates from provider                                                |
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

## License

- csaf_distribution is licensed as Free Software under MIT License.

- See the specific source files
  for details, the license itself can be found in the directory `LICENSES/`.

- Contains third party Free Software components under licenses that to our best knowledge are compatible at time of adding the dependency, [3rdpartylicenses.md](3rdpartylicenses.md) has the details.

- Check the source file of each schema under `/csaf/schema/` to see the source and license of each one.
