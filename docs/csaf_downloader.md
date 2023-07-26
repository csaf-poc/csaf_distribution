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
  -t, --timerange=RANGE            RANGE of time from which advisories to download
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
# timerange       # not set by default
```

The `timerange` parameter enables downloading advisories which last changes falls
into a given intervall. There are three possible notations:

1. Relative. If the given string follows the rules of being a [Go duration](https://pkg.go.dev/time@go1.20.6#ParseDuration)
    the time interval from now minus that duration till now is used. 
    E.g. `"3h"` means downloading the advisories that have changed in the last three hours.

2. Absolute. If the given string is an RFC 3339 date timestamp the time interval between
   this date and now is used. 
   E.g. `"2006-01-02"` means that all files between 2006 January 2nd and now going to being
   downloaded. 
   Accepted patterns are:
   - `"2006-01-02T15:04:05Z"`
   - `"2006-01-02T15:04:05+07:00"`
   - `"2006-01-02T15:04:05-07:00"`
   - `"2006-01-02T15:04:05"`
   - `"2006-01-02T15:04"`
   - `"2006-01-02T15"`
   - `"2006-01-02"`
   - `"2006-01"`
   - `"2006"`

   Missing parts are set to the smallest value possible in that field.

3. Range. Same as 2 but separated by a `,` to span an interval. e.g `2019,2024`
   spans an interval from 1st January 2019 to the 1st January of 2024.

All interval boundaries are inclusive.
