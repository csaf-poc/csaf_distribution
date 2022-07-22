If an organisation publishes their advisories via the internet
as valid CSAF documents, with good filenames and using TLS,
the [CSAF specification](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.md)
calls it a *CASF publisher*.

After manually downloading the advisories from such a publisher,
the tools here can be used to offer the CSAF files for automated downloading
as *CSAF aggregator*.

There three necessary steps, easiest ist to use
one single virtual maschine (or container) per internal provider.
Use a different port for each.
Other setups are possible of course, e.g. virtual hosts
or dynamic setting using nginx configuration methods.


### Setup provider api via FastCGI

Follow the general instructions to setup the `csaf_provider`
as FastCGI binary, but differ in the following way:

Recommended is to use non-standard TLS port to serve
and an internal domain name.

For each internal provider a customized configuration file
must point to a place which can be served via a web server internally
later, for e.g. here is a potential config file to be saved
at `/etc/csaf/internal-provider1.toml`:

```toml
openpgp_private_key = "/etc/csaf/real_private.asc"
openpgp_public_key = "/etc/csaf/real_public.asc"
tlps = ["white"]
canonical_url_prefix = "https://nein.ntvtn.de:10443"
categories = ["Example Company Product A", "expr:document.lang"]
create_service_document = true
folder = "/var/www-p1/"
web = "/var/www-p1/html"
```

For `csaf_provider.go` to find this file, you need to adjust
the paths via a variable, normally set in `/etc/nginx/fcgiwrap.conf`:
```
fastcgi_param CSAF_CONFIG /etc/csaf/internal-provider1.toml;
```
(Careful: setting this variable a second time will transfer both values to
facgiwrap via an array. It is not guarantee that the last value will be
used.  So if you are thinking about setting this variable dynamically,
you need to make sure to set in a general file, but only once elsewhere.)


#### Networking
Make sure the people responsible for doing the manual uploads
can access the port where the CGI script can be called.


### Setup internal CSAF provider

Now serve the written `html` directory via a webserver, but only
internally. For nginx, you can follow the setup docs and for example
limit the interfaces where it is listening in the `listen` directive.
The following setting will only respond to requests
on the loopback interface on port 10443 with TLS.

```
  listen localhost:10443 ssl default_server;
  listen [::1]:10443 ssl default_server;
```

(Don't forget to reload nginx, so it gets the config change.)


#### Networking
Make sure the port can be reached by the server
where the `csaf_aggregator` is started, but cannot be reached from
an outside system.

This could be done by an ssh (or other VPN) tunnel.


### Add to aggregator configuration

#### Networking
Make sure that you have a local domain name that resolves
to our internal provider host, but is fine to be exposed in public.
As the domain name can be seen in the resulting `aggregator.json`.

One simple method to do this, is by using an entry in
`/etc/hosts`:

```
192.168.2.2       nein.ntvtn.de
```

Consult your network admin for a secure setup.


#### aggregator.toml
Add a section to the aggregator configuration file,
to it is used next time when `csaf_aggregator` does a full run, e.g.:

```toml
[[providers]]
  name = "Example Proxy Provider"
  domain = "https://nein.ntvtn.de:10443/.well-known/csaf/provider-metadata.json"
```

Only makes sense if aggregator.category is set to `aggregator` (mirror mode).

Depending on how you do the "tunneling" you can add `insecure = true`
to the section, if you are sure if nobody can mess with your internal DNS.
This deactivates the checking of the root for the TLS certificate.
Alternatively you can import the cert of the root CA for the internal
provider to the system root certificate store, which `csaf_aggregator`
is using.


