## csaf_downloader
A tool to download CSAF documents from CSAF providers.

### Usage

```
csaf_downloader [OPTIONS] domain...

Application Options:
  -d, --directory=DIR              DIRectory to store the downloaded files in
      --insecure                   Do not check TLS certificates from provider
      --ignoresigcheck             Ignore signature check results, just warn on mismatch
      --version                    Display version of the binary
  -v, --verbose                    Verbose output
  -r, --rate=                      The average upper limit of https operations per second (defaults to unlimited)
  -w, --worker=NUM                 NUMber of concurrent downloads (default: 2)
  -H, --header=                    One or more extra HTTP header fields
      --validator=URL              URL to validate documents remotely
      --validatorcache=FILE        FILE to cache remote validations
      --validatorpreset=PRESETS    One or more PRESETS to validate remotely (default: [mandatory])
  -c, --config=TOML-FILE           Path to config TOML file

Help Options:
  -h, --help                       Show this help message
```

Will download all CSAF documents for the given _domains_, by trying each as a CSAF provider.

If a _domain_ starts with `https://` it is instead considered a direct URL to the `provider-metadata.json` and downloading procedes from there.

Increasing the number of workers opens more connections to the web servers
to download more advisories at once. This may improve the overall speed of the download.
However, since this also increases the load on the servers, their administrators could
have taken countermeasures to limit this.

If no config file is explictly given the follwing places are searched for a config file:
```
~/.config/csaf/downloader.toml
~/.csaf_downloader.toml
csaf_downloader.toml
```

with `~` expanding to `$HOME` on unixoid systems and `%HOMEPATH` on Windows systems.

Supported options in config files:
```
directory         # not set by default
insecure          = false
ignoresigcheck    = false
verbose           = false
# rate            # set to unlimited
worker            = 2
# header          # not set by default
# validator       # not set by default
# validatorcache  # not set by default
validatorpreset   = ["mandatory"]
```
