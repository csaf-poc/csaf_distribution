# csaf_distribution

An implementation of a
[CSAF 2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html)
trusted provider, checker, aggregator and downloader.
Includes an uploader command line tool for the trusted provider.

## Tools for users
### [csaf_downloader](docs/csaf_downloader.md)
is a tool for downloading advisories from a provider.
Can be used for automated forwarding of CSAF documents.

### [csaf_validator](docs/csaf_validator.md)
is a tool to validate local advisories files against the JSON Schema and an optional remote validator.

## Tools for advisory providers

### [csaf_provider](docs/csaf_provider.md)
is an implementation of the role CSAF Trusted Provider, also offering
a simple HTTPS based management service.

### [csaf_uploader](docs/csaf_uploader.md)
is a command line tool to upload CSAF documents to the `csaf_provider`.

### [csaf_checker](docs/csaf_checker.md)
is a tool for testing a CSAF Trusted Provider according to [Section 7 of the CSAF standard](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html#7-distributing-csaf-documents).

### [csaf_aggregator](docs/csaf_aggregator.md)
is a CSAF Aggregator, to list or mirror providers.

## Other stuff

### [examples](./examples/README.md)
are small examples of how to use `github.com/csaf-poc/csaf_distribution`
as an API. Currently this is a work in progress, as usage of this repository
as a library to access is _not officially supported_, e.g.
see https://github.com/csaf-poc/csaf_distribution/issues/367 .

## Setup
Binaries for the server side are only available and tested
for GNU/Linux-Systems, e.g. Ubuntu LTS.
They are likely to run on similar systems when build from sources.

The windows binary package only includes
`csaf_downloader`, `csaf_validator`, `csaf_checker` and `csaf_uploader`.

The MacOS binary archives come with the same set of client tools
and are _community supported_. Which means:
while they are expected to run fine,
they are not at the same level of testing and maintenance
as the Windows and GNU/Linux binaries.


### Prebuild binaries

Download the binaries from the most recent release assets on Github.


### Build from sources

- A recent version of **Go** (1.20+) should be installed. [Go installation](https://go.dev/doc/install)

- Clone the repository `git clone https://github.com/csaf-poc/csaf_distribution.git `

- Build Go components Makefile supplies the following targets:
	- Build for GNU/Linux system: `make build_linux`
    - Build for Windows system (cross build): `make build_win`
    - Build for macOS system on Intel Processor (AMD64) (cross build): `make build_mac_amd64`
    - Build for macOS system on Apple Silicon (ARM64) (cross build): `make build_mac_arm64`
    - Build For GNU/Linux, macOS and Windows: `make build`
	- Build from a specific git tag by passing the intended tag to the `BUILDTAG` variable.
	   E.g. `make BUILDTAG=v1.0.0 build` or `make BUILDTAG=1 build_linux`.
     The special value `1` means checking out the highest git tag for the build.
    - Remove the generated binaries und their directories: `make mostlyclean`

Binaries will be placed in directories named like `bin-linux-amd64/` and `bin-windows-amd64/`.

### Setup (Trusted Provider)

- [Install](https://nginx.org/en/docs/install.html) **nginx**
- To install a TLS server certificate on nginx see [docs/install-server-certificate.md](docs/install-server-certificate.md)
- To configure nginx see [docs/provider-setup.md](docs/provider-setup.md)
- To configure nginx for client certificate authentication see [docs/client-certificate-setup.md](docs/client-certificate-setup.md)

### Development

For further details of the development process consult our [development page](./docs/Development.md).


## License

- `csaf_distribution` is licensed as Free Software under MIT License.

- See the specific source files
  for details, the license itself can be found in the directory `LICENSES/`.

- Contains third party Free Software components under licenses that to our best knowledge are compatible at time of adding the dependency, [3rdpartylicenses.md](3rdpartylicenses.md) has the details.

- Check the source file of each schema under `/csaf/schema/` to see the source and license of each one.
