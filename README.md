# csaf_distribution

**WIP**: A prove of concept for a CSAF trusted provider, checker and aggregator.


## Setup

- A recent version of **Go** (1.17+) should be installed. [Go installation](https://go.dev/doc/install)

- Clone the repository `git clone https://github.com/csaf-poc/csaf_distribution.git `

- Build Go components
 ``` bash
 cd csaf_distribution
 go build -v ./cmd/...
```

- [Install](http://nginx.org/en/docs/install.html)  **nginx**
- To configure nginx see [docs/provider-setup.md](docs/provider-setup.md)
