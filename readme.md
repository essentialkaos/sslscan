# SSLScan [![GoDoc](https://godoc.org/pkg.re/essentialkaos/sslscan.v5?status.svg)](https://godoc.org/pkg.re/essentialkaos/sslscan.v5) [![Go Report Card](https://goreportcard.com/badge/github.com/essentialkaos/sslscan)](https://goreportcard.com/report/github.com/essentialkaos/sslscan) [![Codebeat](https://codebeat.co/badges/59a17b0e-b974-425e-a442-b9bcc3ccf7c0)](https://codebeat.co/projects/github-com-essentialkaos-sslscan) [![License](https://gh.kaos.io/apache2.svg)](LICENSE)

Package for Go for working with [SSLLabs](https://www.ssllabs.com) public API.

## Installation

Before the initial install allows git to use redirects for [pkg.re](https://github.com/essentialkaos/pkgre) service (reason why you should do this described [here](https://github.com/essentialkaos/pkgre#git-support)):

```
git config --global http.https://pkg.re.followRedirects true
```

To build the SSLScan from scratch, make sure you have a working Go 1.5+ workspace ([instructions](https://golang.org/doc/install)), then:

```
go get pkg.re/essentialkaos/sslscan.v5
```

If you want update SSLScan package to latest stable release, do:

```
go get -u pkg.re/essentialkaos/sslscan.v5
```

## Build Status

| Branch | Status |
|------------|--------|
| `master` | [![Build Status](https://travis-ci.org/essentialkaos/sslscan.svg?branch=master)](https://travis-ci.org/essentialkaos/sslscan) |
| `develop` | [![Build Status](https://travis-ci.org/essentialkaos/sslscan.svg?branch=develop)](https://travis-ci.org/essentialkaos/sslscan) |

## Contributing

Before contributing to this project please read our [Contributing Guidelines](https://github.com/essentialkaos/contributing-guidelines#contributing-guidelines).

## Terms of Use

This project is not affiliated with SSL Labs and not officially supported by SSL Labs. Before using this package please read [Qualys SSL Labs Terms of Use](https://www.ssllabs.com/downloads/Qualys_SSL_Labs_Terms_of_Use.pdf).

Also you should:

* Only inspect sites and servers whose owners have given you permission to do so;
* Be clear that this tool works by sending assessment requests to remote SSL Labs servers and that this information will be shared with them.

## License

[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
