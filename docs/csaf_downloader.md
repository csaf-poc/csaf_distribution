## csaf_downloader
A tool to download CSAF content from a specific domain/provider.

### Usage

```
csaf_downloader [OPTIONS] domain...

Application Options:
  -d, --directory=DIR          DIRectory to store the downloaded files in
      --insecure               Do not check TLS certificates from provider
      --version                Display version of the binary
  -v, --verbose                Verbose output
  -r, --rate=                  The average upper limit of https operations per second
  -H, --header=                One or more extra HTTP header fields
      --validator=URL          URL to validate documents remotely
      --validatorcache=FILE    FILE to cache remote validations
      --validatorpreset=       One or more presets to validate remotely (default: mandatory)

Help Options:
  -h, --help                   Show this help message
```

The downloader will attempt to download from the given domain URL. 
A direct URL to the metadata.json can be given by starting the URL with
`https://`. Otherwise the downloader will attempt to find the metadata.json
in any of valid default location.
