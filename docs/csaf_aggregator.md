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

Usage example for a single run, to test if the config is good:
```bash
./csaf_aggregator -c docs/examples/aggregator.toml
```

Once the config is good, you can run the aggregator periodically
in two modes. For instance using `cron` on Ubuntu and after placing
the config file in `/etc/csaf_aggregator.toml`:

```bash
mkdir /var/log/csaf_aggregator
mkdir ~www-data/bin
cp bin-linux-amd64/csaf_aggregator ~www-data/bin/
chown www-data.www-data -R ~www-data/bin /var/log/csaf_aggregator

# list current crontab
crontab -u www-data -l
# edit crontab (add lines like example below)
crontab -u www-data -e
```

Crontab example, running the full mode one a day and updating
interim advisories every 60 minutes:

```crontab
SHELL=/bin/bash
# run full mode in the night at 04:00
0 4 * * * $HOME/bin/csaf_aggregator --config /etc/csaf_aggregator.toml >> /var/log/csaf_aggregator/full.log 2>&1
# run in interim mode once per hour at 30 minutes, e.g. 00:30, 01:30, ...
30 0-23 * * * $HOME/bin/csaf_aggregator --config /etc/csaf_aggregator.toml --interim >> /var/log/csaf_aggregator/interim.log 2>&1
```


### config options

The following options can be used in the config file in TOML format:

```
workers  // number of parallel workers to start (default 10)
folder   // target folder on disc for writing the downloaded documents
web      // directory to be served by the webserver
domain   // base url where the contents will be reachable from outside
rate     // overall downloading limit per worker
insecure // do not check validity of TLS certificates
aggregator    // table with basic infos for the aggregator object
providers     // array of tables, each entry to be mirrored or listed
key           // OpenPGP key
openpgp_url   // URL where the OpenPGP public key part can be found
passphrase    // passphrase of the OpenPGP key
lock_file     // path to lockfile, to stop other instances if one is not done
interim_years // limiting the years for which interim documents are searched
verbose       // print more diagnostic output, e.g. https request
allow_single_provider // debugging option
```

Rates are specified as floats in HTTPS operations per second.
0 means no limit.

`providers` is an array of tables, each allowing
```
name
domain
rate
insecure
```

#### Example config file
<!-- MARKDOWN-AUTO-DOCS:START (CODE:src=../docs/examples/aggregator.toml) -->
<!-- The below code snippet is automatically added from ../docs/examples/aggregator.toml -->
```toml
workers = 2
folder = "/var/csaf_aggregator"
lock_file = "/var/csaf_aggregator/run.lock"
web = "/var/csaf_aggregator/html"
domain = "https://localhost:9443"
rate = 10.0
insecure = true

[aggregator]
  category = "aggregator"
  name = "Example Development CSAF Aggregator"
  contact_details = "some @ somewhere"
  issuing_authority = "This service is provided as it is. It is gratis for everybody."
  namespace = "https://testnamespace.example.org"

[[providers]]
  name = "local-dev-provider"
  domain = "localhost"
#  rate = 1.5
#  insecure = true

[[providers]]
  name = "local-dev-provider2"
  domain = "localhost"
#  rate = 1.2
#  insecure = true

#key =
#passphrase =

# specification requires at least two providers (default),
# to override for testing, enable:
# allow_single_provider = true
```
<!-- MARKDOWN-AUTO-DOCS:END -->
