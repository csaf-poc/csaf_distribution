## Provider options
Following options are supported:

 - password: Authentication password for accessing the CSAF provider.
 - key: The private OpenPGP key.
 - folder: Specify the root folder. Default: `/var/www/`.
 - web: Specify the web folder. Default: `/var/www/html`.
 - tlps: Set the allowed TLP comming with the upload request (one or more of "csaf", "white", "amber", "green", "red").
   The "csaf" selection lets the provider takes the value from the CSAF document.
   These affects the list items in the web interface.
   Default: `["csaf", "white", "amber", "green", "red"]`.
 - upload_signature: Send signature with the request, an additional input-field in the web interface will be shown to let user enter an ascii armored signature. Default: `false`.
 - openpgp_url: URL to OpenPGP key-server. Default: `https://openpgp.circl.lu`.
 - canonical_url_prefix: start of the URL where contents shall be accessible from the internet. Default: `https://$SERVER_NAME`.
 - no_passphrase: Let user send password with the request, if set to true the input-field in the web interface will be disappeared. Default: `false`.
 - no_validation: Validate the uploaded CSAF document against the JSON schema. Default: `false`.
 - no_web_ui: Disable the web interface. Default: `false`.
 - dynamic_provider_metadata: Take the publisher from the CSAF document. Default: `false`.
 - provider_metadata: Configure the provider metadata.
 - provider_metadata.list_on_CSAF_aggregators: List on aggregators
 - provider_metadata.mirror_on_CSAF_aggregators: Mirror on aggregators
 - provider_metadata.publisher: Set the publisher. Default: `{"category"= "vendor", "name"= "Example", "namespace"= "https://example.com"}`.
 - upload_limit: Set the upload limit  size of the file. Default: `50 MiB`.
 - issuer: The issuer of the CA, which if set, restricts the writing permission and the accessing to the web-interface to only the client certificates signed with this CA.
