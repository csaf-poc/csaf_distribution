## csaf_checker

Following options are supported:

| Options                                    | Description                                    |
| ------------------------------------------ | ---------------------------------------------- |
| -o, --output=REPORT-FILE                   | File name of the generated report              |
| -f, --format=[json                         | html]                                          |
| -t, --tlp=[csaf\|white\|green\|amber\|red] | Format of report (default: json)               |
| --insecure                                 | o not check TLS certificates from provider     |
| --client-cert=CERT-FILE                    | TLS client certificate file (PEM encoded data) |
| --client-key=KEY-FILE                      | TLS client private key file (PEM encoded data) |
| --version                                  | Display version of the binary                  |

Usage example:
` ./csaf_checker example.com -f html -o check-results.html`
