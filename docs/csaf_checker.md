## csaf_checker

### Usage

```
  csaf_checker [OPTIONS]

Application Options:
  -o, --output=REPORT-FILE       File name of the generated report
  -f, --format=[json|html]       Format of report (default: json)
      --insecure                 Do not check TLS certificates from provider
      --client-cert=CERT-FILE    TLS client certificate file (PEM encoded data)
      --client-key=KEY-FILE      TLS client private key file (PEM encoded data)
      --version                  Display version of the binary
  -v, --verbose                  Verbose output
  -r, --rate=                    The average upper limit of https operations
                                 per second

Help Options:
  -h, --help                     Show this help message
```

Usage example:
` ./csaf_checker example.com -f html --rate=5.3 -o check-results.html`

Each performed check has a return type of either 0,1 or 2:
```
type 0: success
type 1: warning
type 2: error
```

The checker result is a success if no checks resulted in type 2, and a failure otherwise. 
