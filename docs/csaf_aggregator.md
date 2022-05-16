## csaf_aggregator

### Usage

```
  csaf_aggregator [OPTIONS]

Application Options:
  -c, --config=CFG-FILE    File name of the configuration file (default:
                           aggregator.toml)
      --version            Display version of the binary
  -i, --interim            Perform an interim scan

Help Options:
  -h, --help               Show this help message
```

Usage example:
``` ./csaf_aggregator -c docs/examples/aggregator.toml ```

### config options

*todo*

```
workers
folder
web
domain
rate
insecure
aggregator
providers
key
openpgp_url
passphrase
allow_single_provider
lock_file
interim_years
```

`providers` is a list of tables, each allowing
```
name
domain
rate
insecure
```

