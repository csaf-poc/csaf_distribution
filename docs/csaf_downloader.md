## csaf_downloader
A tool to download CSAF documents from CSAF providers.

### Usage

```
csaf_downloader [OPTIONS] domain...

Application Options:
  -d, --directory=DIR          DIRectory to store the downloaded files in
      --insecure               Do not check TLS certificates from provider
      --ignoresigcheck         Ignore signature check results, just warn on mismatch
      --version                Display version of the binary
  -v, --verbose                Verbose output
  -r, --rate=                  The average upper limit of https operations per second (defaults to unlimited)
  -w, --worker=NUM             NUMber of concurrent downloads (default: 2)
  -H, --header=                One or more extra HTTP header fields
      --validator=URL          URL to validate documents remotely
      --validatorcache=FILE    FILE to cache remote validations
      --validatorpreset=       One or more presets to validate remotely (default: mandatory)

Help Options:
  -h, --help                   Show this help message
```

Will download all CSAF documents for the given _domains_, by trying each as a CSAF provider.

If a _domain_ starts with `https://` it is instead considered a direct URL to the `provider-metadata.json` and downloading procedes from there.

Increasing the number of workers opens more connections to the web servers
to download more advisories at once. This may improve the overall speed of the download.
However, since this also increases the load on the servers, their administrators could
have taken countermeasures to limit this.
