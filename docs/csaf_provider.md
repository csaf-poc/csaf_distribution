`csaf_provider` implements the CGI interface for webservers
and reads its configuration from a [TOML](https://toml.io/en/) file.
The [setup docs](../README.md#setup-trusted-provider)
explain how to wire this up with nginx and where the config file lives.


## Provider options
An example TOML file with all config options and default values:

```toml
#Authentication password for accessing the CSAF provider.
#password = ""

# Path to public OpenPGP key.
#openpgp_public_key = "usr/lib/csaf/openpgp_public.asc"

# The private OpenPGP key
#openpgp_private_key = "/usr/lib/csaf/openpgp_private.asc"

# Specify the root folder `
#folder = "/var/www/"

# Specify the web folder
#web = "/var/www/html"

# Send signature with the request, an additional input-field in the web interface will be shown to let user enter an ascii armored signature.
#upload_signature = false

# start of the URL where contents shall be accessible from the internet.
#canonical_url_prefix  = "https://$SERVER_NAME"

# Let user send password with the request, if set to true the input-field in the web interface will be disappeared.
#no_passphrase = false

# Validate the uploaded CSAF document against the JSON schema.
#no_validation = false

# Disable the web interface.
#no_web_ui = false

# Take the publisher from the CSAF document.
#dynamic_provider_metadata = false

# Set the upload limit size of a file in bytes. Default: `52428800` (aka 50 MiB).
#upload_limit =  52428800

# The issuer of the CA, which if set, restricts the writing permission and the accessing to the web-interface to only the client certificates signed with this CA.
#issuer = ""

# Set the allowed TLP comming with the upload request (one or more of "csaf", "white", "amber", "green", "red").
#   The "csaf" selection lets the provider takes the value from the CSAF document.
#   These affects the list items in the web interface.
#tlps = ["csaf", "white", "amber", "green", "red"]`

# Use a remote validator service. Not used by default.
#[remote_validator]
#url = "http://localhost:3000"
#presets = ["mandatory"]
#cache = "/var/lib/csaf/validations.db"

[provider_metadata]
# List on aggregators
list_on_CSAF_aggregators = true
#Mirror on aggregators
mirror_on_CSAF_aggregators = true
[provider_metadata.publisher]
category = "vendor"
name = "Example Company"
namespace = "https://example.com"
issuing_authority = "We at Example Company are responsible for publishing and maintaining Product Y."
contact_details = "Example Company can be reached at contact_us@example.com, or via our website at https://www.example.com/contact."
```
