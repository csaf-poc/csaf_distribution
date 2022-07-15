`csaf_provider` implements the CGI interface for webservers
and reads its configuration from a [TOML](https://toml.io/en/) file.
The [setup docs](../README.md#setup-trusted-provider)
explain how to wire this up with nginx and where the config file lives.


## Provider options

Following options are supported in the config file:

 - password: Authentication password for accessing the CSAF provider.
 - openpgp_public_key: The public OpenPGP key. Default: `/ust/lib/csaf/openpgp_public.asc`
 - openpgp_private_key: The private OpenPGP key. Default: `/ust/lib/csaf/openpgp_private.asc`
 - folder: Specify the root folder. Default: `/var/www/`.
 - web: Specify the web folder. Default: `/var/www/html`.
 - upload_signature: Send signature with the request, an additional input-field in the web interface will be shown to let user enter an ascii armored signature. Default: `false`.
 - canonical_url_prefix: start of the URL where contents shall be accessible from the internet. Default: `https://$SERVER_NAME`.
 - certificate_and_password: Require password and a valid Client Certificate for write access. Default: false
 - no_passphrase: Let the user send the request without having to send a password. If set to true, the input-field in the web interface will be omitted. Default: `false`.
 - no_validation: Skip validation of the uploaded CSAF document against the JSON schema. Default: `false`.
 - no_web_ui: Disable the web interface. Default: `false`.
 - dynamic_provider_metadata: Take the publisher from the CSAF document. Default: `false`.
 - upload_limit: Set the upload limit size of a file in bytes. Default: `52428800` (aka 50 MiB).
 - issuer: The issuer of the CA, which if set, restricts the writing permission and the accessing to the web-interface to only the client certificates signed with this CA.
 - write_indices: Write/update `index.txt` and `changes.csv`. Default: false
 - write_security: Write `CSAF:` entry into `security.txt`: Default: false
 - tlps: Set the allowed TLP comming with the upload request (one or more of "csaf", "white", "amber", "green", "red").
   The "csaf" selection lets the provider takes the value from the CSAF document.
   These affects the list items in the web interface.
   Default: `["csaf", "white", "amber", "green", "red"]`.
 - create_service_document: Create ROLIE service document. Default: false
 - categories: Create ROLIE category document from a list of strings.
   If a list item starts with `expr:` the rest of the string is used as a [JsonPath expression](https://goessner.net/articles/JsonPath/) to
   extract a string from the incoming advisories. Strings not starting with `expr:` are took verbatim.
   By default no category documents are created.
   E.g: `categories = ["Example Company Product A", "expr:document.lang"]`
 - provider_metadata: Configure the provider metadata.
 - provider_metadata.list_on_CSAF_aggregators: List on aggregators
 - provider_metadata.mirror_on_CSAF_aggregators: Mirror on aggregators
 - remote_validator: Use a remote validator service. Not used by default.
   `{ "url" = "http://localhost:3000", "presets" = ["mandatory"], "cache" = "/var/lib/csaf/validations.db" }`
 - provider_metadata.publisher: Set the publisher. Default:
```toml
[provider_metadata.publisher]
category = "vendor"
name = "Example Company"
namespace = "https://example.com"
issuing_authority = "We at Example Company are responsible for publishing and maintaining Product Y."
contact_details = "Example Company can be reached at contact_us@example.com, or via our website at https://www.example.com/contact."
```
