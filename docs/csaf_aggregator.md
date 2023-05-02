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
in two modes: full and interim.

Here is a complete example using `cron` on Ubuntu. After placing
the config file in `/etc/csaf_aggregator.toml` and making sure
its permissions only allow the user `www-data` to read it:

```bash
chown www-data /etc/csaf_aggregator.toml
chmod go-rwx /etc/csaf_aggregator.toml

mkdir /var/log/csaf_aggregator
mkdir ~www-data/bin
cp bin-linux-amd64/csaf_aggregator ~www-data/bin/
chown www-data.www-data -R ~www-data/bin /var/log/csaf_aggregator

# list current crontab
crontab -u www-data -l
# edit crontab (add lines like example below)
crontab -u www-data -e
```

Here is a crontab that runs the full mode once a day and updating
interim advisories every 60 minutes:

```crontab
SHELL=/bin/bash
# run full mode in the night at 04:00
0 4 * * * $HOME/bin/csaf_aggregator --config /etc/csaf_aggregator.toml >> /var/log/csaf_aggregator/full.log 2>&1
# run in interim mode once per hour at 30 minutes, e.g. 00:30, 01:30, ...
30 0-23 * * * $HOME/bin/csaf_aggregator --config /etc/csaf_aggregator.toml --interim >> /var/log/csaf_aggregator/interim.log 2>&1
```


#### serve via web server

Serve the paths where the aggregator writes its `html/` output
by means of a webserver.
In the config example below the place in the filesystem
is configured by the path given for `web`.

The user running the aggregator has to be able to write there
and the web server must be able to read the files.

If you are using nginx, the setup instructions for the provider give
a template. For the aggregator the difference is that you can leave out
the cgi-bin part, potentially commend out the TLS client parts and
adjust the `root` path accordingly.


### config options

The config file is written in [TOML](https://toml.io/en/v1.0.0).
Each _key_ in the following table is optional and
can be used directly in the file. If given it overrides the internal default.

```go
workers                 // number of parallel workers to start (default 10)
folder                  // target folder on disc for writing the downloaded documents (default "/var/www")
web                     // directory to be served by the webserver (default "/var/www/html")
domain                  // base url where the contents will be reachable from outside (default "https://example.com")
rate                    // downloading limit per worker in HTTPS req/s (defaults to unlimited)
insecure                // do not check validity of TLS certificates
write_indices           // write index.txt and changes.csv
update_interval         // to indicate the collection interval for a provider (default ""on best effort")
create_service_document // write a service.json to the ROLIE feed docs for a provider (default false)
categories              // configure ROLIE category values for a provider
openpgp_private_key     // OpenPGP private key (must have no passphrase set, if
                        // you want to be able to run unattended, e.g. via cron.)
openpgp_public_key      // OpenPGP public key
passphrase              // passphrase of the OpenPGP key
lock_file               // path to lockfile, to stop other instances if one is not done (default:/var/lock/csaf_aggregator/lock, disable by setting it to "")
interim_years           // limiting the years for which interim documents are searched (default 0)
verbose                 // print more diagnostic output, e.g. https requests (default false)
allow_single_provider   // debugging option (default false)
```

Next we have two TOML _tables_:

```
aggregator            // basic infos for the aggregator object
remote_validator      // config for optional remote validation checker
```
[See the provider config](csaf_provider.md#provider-options) about
how to configure `remote_validator`.

At last there is the TOML _array of tables_:
```
providers             // each entry to be mirrored or listed
```

where at least 2 providers have to be configured.
With each _table_ allowing:

```
name
domain
rate
insecure
write_indices
category
update_interval
create_service_document
categories
```

Where valid `name` and `domain` settings are required.

If you want an entry to be listed instead of mirrored
in a `aggregator.category == "aggregator"` instance,
set `category` to `lister` in the entry.
Otherwise it is recommended to not set `category` for entries.

The remaining _keys_ per entry in the _table_ `providers`
are optional and will take precedence instead
of the directly given _keys_ in the TOML file and the internal defaults.

If a provider's `domain` starts with `https://` it is considered a publisher.
These publishers are added to the `csaf_publishers` list, which is written
to the `aggregator.json`.

To offer an easy way of assorting CSAF documents by criteria like
document category, languages or values of the branch category within
the product tree, ROLIE category values can be configured in `categories`.
This can either
be done using an array of strings taken literally or, by prepending `"expr:"`. 
The latter is evaluated as JSONPath and the result will be added into the 
categories document. For a more detailed explanation and examples,
[refer to the provider config](csaf_provider.md#provider-options).


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
#openpgp_private_key =
#openpgp_public_key =
#interim_years =
#passphrase =
#write_indices = false

# specification requires at least two providers (default),
# to override for testing, enable:
# allow_single_provider = true

[aggregator]
  # Set if this instance shall be a mirror (aka `aggregator`) or a `lister`.
  # This determines the default value for the entries in [[provider]].
  category = "aggregator"
  name = "Example Development CSAF Aggregator"
  contact_details = "some @ somewhere"
  issuing_authority = "This service is provided as it is. It is gratis for everybody."
  namespace = "https://testnamespace.example.org"

[[providers]]
  name = "local-dev-provider"
  domain = "localhost"
  categories = ["Example Company Product A", "expr:document.lang"]
  create_service_document = true
#  rate = 1.5
#  insecure = true

[[providers]]
  name = "local-dev-provider2"
  domain = "https://localhost:8443/.well-known/csaf/provider-metadata.json"
#  rate = 1.2
#  insecure = true
  write_indices = true

[[providers]]
  name = "local-dev-provider3"
  domain = "localhost"
#  rate = 1.8
#  insecure = true
  write_indices = true
  # If aggregator.category == "aggregator", set for an entry that should
  # be listed in addition:
  category = "lister"
```
<!-- MARKDOWN-AUTO-DOCS:END -->


#### Publish others' advisories

In case you want to provide CSAF advisories from others
that only qualify as CSAF publishers, see
[how to use the `csaf_aggregator` as "CSAF proxy provider"](proxy-provider-for-aggregator.md).
