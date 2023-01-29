## csaf_validator

is a tool to validate local advisories files against the JSON Schema and an optional remote validator.

### Usage

```
csaf_validator [OPTIONS] files...

Application Options:
      --version                Display version of the binary
      --validator=URL          URL to validate documents remotely
      --validatorcache=FILE    FILE to cache remote validations
      --validatorpreset=       One or more presets to validate remotely (default: mandatory)

Help Options:
  -h, --help                   Show this help message
```
