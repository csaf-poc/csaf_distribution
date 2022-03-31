Scripts for assisting the Integration tests. They are written on Ubuntu 20.04 TLS amd64.

- `prepareUbunutForITest.sh` installs the required packages for the csaf_distribution integration tests on a naked ubuntu 20.04 LTS amd64.

- `TLSConfigsForITest.sh` Generates a root CA and webserver cert by running `createRootCAForITest.sh` and `createWebserverCertForITest.sh`
and configures nginx for serving TLS connections.

- `setupProviderForITest.sh` builds the csaf_provider, writes the required nginx configurations and create the initial folders.
