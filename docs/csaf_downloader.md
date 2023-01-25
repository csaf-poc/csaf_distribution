## csaf_downloader
A tool to download CSAF content from a specific domain/provider.

### Usage

```
csaf_downloader [OPTIONS] domain...

Application Options:
  -d, --directory= Directory to store the downloaded files in
      --insecure   Do not check TLS certificates from provider
      --version    Display version of the binary
  -v, --verbose    Verbose output
  -r, --rate=      The average upper limit of https operations per second
  -H, --header=    One or more extra HTTP header fields

Help Options:
  -h, --help       Show this help message
```
