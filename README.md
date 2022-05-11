# csaf_distribution

**WIP**: A proof of concept for a CSAF trusted provider, checker and aggregator.

Status: Beta

## [csaf_provider](docs/csaf_components/csaf_provider.md)
Provider is an implementation of the role CSAF Provider of the
[CSAF 2.0 specification](https://docs.oasis-open.org/csaf/csaf/v2.0/csd02/csaf-v2.0-csd02.html).

## [csaf_aggregator](docs/csaf_components/csaf_aggregator.md)
Aggeragator is an implementation of the role CSAF Aggregator of the
[CSAF 2.0 specification](https://docs.oasis-open.org/csaf/csaf/v2.0/csd02/csaf-v2.0-csd02.html).

## [csaf_checker](docs/csaf_components/csaf_checker.md)
Provider checker is a tool for testing a CSAF trusted provider according to [Section 7 of the CSAF standard](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html#7-distributing-csaf-documents).

## [csaf_uploader](docs/csaf_components/csaf_uploader.md)
Uploader is a command line tool that uploads CSAF documents to the trusted provider (CSAF_Provider).
Following options are supported:


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
- To configure nginx for client certificate authentication see [docs/client-certificate-setup.md](docs/client-certificate-setup.md)


which asks to enter password interactively.


## License

- csaf_distribution is licensed as Free Software under MIT License.

- See the specific source files
  for details, the license itself can be found in the directory `LICENSES/`.

- Contains third party Free Software components under licenses that to our best knowledge are compatible at time of adding the dependency, [3rdpartylicenses.md](3rdpartylicenses.md) has the details.

- Check the source file of each schema under `/csaf/schema/` to see the source and license of each one.
