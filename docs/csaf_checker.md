## csaf_checker

### Usage

```
Usage:
  csaf_checker [OPTIONS] target...

Application Options:
  -o, --output=REPORT-FILE       File name of the generated report
  -f, --format=[json|html]       Format of report (default: json)
      --insecure                 Do not check TLS certificates from provider
      --client-cert=CERT-FILE    TLS client certificate file (PEM encoded data)
      --client-key=KEY-FILE      TLS client private key file (PEM encoded data)
      --version                  Display version of the binary
  -v, --verbose                  Verbose output
  -r, --rate=                    The average upper limit of https operations per second
  -y, --years=YEARS              Number of years to look back from now
  -H, --header=                  One or more extra HTTP header fields
      --validator=URL            URL to validate documents remotely
      --validatorcache=FILE      FILE to cache remote validations
      --validatorpreset=         One or more presets to validate remotely (default: mandatory)


Help Options:
  -h, --help                     Show this help message
```

The checker attempts to check each given _target_.

If a _target_ start with `https://` it is considered
a direct URL to the `provider-metadata.json`.

Else it will be treated as a _domain_ for which the
`provider-metadata.json` shall be found as documented in the CSAF standard.

Usage example:
` ./csaf_checker example.com -f html --rate=5.3 -H apikey:SECRET -o check-results.html`

Each performed check has a return type of either 0,1 or 2:
```
type 0: success
type 1: warning
type 2: error
```

The checker result is a success if no checks resulted in type 2, and a failure otherwise. 


### Remarks

The `role` given in the `provider-metadata.json` is not
yet considered to change the overall result,
see https://github.com/csaf-poc/csaf_distribution/issues/221 .
