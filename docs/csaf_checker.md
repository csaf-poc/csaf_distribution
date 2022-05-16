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

Help Options:
  -h, --help                     Show this help message
```

Usage example:
` ./csaf_checker example.com -f html -o check-results.html`
