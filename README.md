<p align="center"><a href="#readme"><img src="https://gh.kaos.st/sslscan.svg"/></a></p>

<p align="center">
  <a href="https://pkg.go.dev/pkg.re/essentialkaos/sslscan.v12"><img src="https://gh.kaos.st/godoc.svg" alt="PkgGoDev"></a>
  <a href="https://goreportcard.com/report/github.com/essentialkaos/sslscan"><img src="https://goreportcard.com/badge/github.com/essentialkaos/sslscan"></a>
  <a href="https://codebeat.co/projects/github-com-essentialkaos-sslscan"><img src="https://codebeat.co/badges/59a17b0e-b974-425e-a442-b9bcc3ccf7c0"></a>
  <a href="https://github.com/essentialkaos/sslscan/actions"><img src="https://github.com/essentialkaos/sslscan/workflows/CI/badge.svg" alt="GitHub Actions Status" /></a>
  <a href="https://github.com/essentialkaos/sslscan/actions?query=workflow%3ACodeQL"><img src="https://github.com/essentialkaos/sslscan/workflows/CodeQL/badge.svg" /></a>
  <a href="#license"><img src="https://gh.kaos.st/apache2.svg"></a>
</p>

<p align="center"><a href="#installation">Installation</a> • <a href="#build-status">Build Status</a> • <a href="#contributing">Contributing</a> • <a href="#terms-of-use">Terms of Use</a> • <a href="#license">License</a></p>

<br/>

Package for Go for working with [SSLLabs](https://www.ssllabs.com) public API.

### Installation

To build the SSLScan from scratch, make sure you have a working Go 1.14+ workspace ([instructions](https://golang.org/doc/install)), then:

```
go get pkg.re/essentialkaos/sslscan.v12
```

If you want update SSLScan package to latest stable release, do:

```
go get -u pkg.re/essentialkaos/sslscan.v12
```

### Build Status

| Branch | Status |
|--------|--------|
| `master` | [![CI](https://github.com/essentialkaos/sslscan/workflows/CI/badge.svg?branch=master)](https://github.com/essentialkaos/sslscan/actions) |
| `develop` | [![CI](https://github.com/essentialkaos/sslscan/workflows/CI/badge.svg?branch=develop)](https://github.com/essentialkaos/sslscan/actions) |

### Contributing

Before contributing to this project please read our [Contributing Guidelines](https://github.com/essentialkaos/contributing-guidelines#contributing-guidelines).

### Terms of Use

This project is not affiliated with SSL Labs and not officially supported by SSL Labs. Before using this package please read [Qualys SSL Labs Terms of Use](https://www.ssllabs.com/downloads/Qualys_SSL_Labs_Terms_of_Use.pdf).

Also you should:

* Only inspect sites and servers whose owners have given you permission to do so;
* Be clear that this tool works by sending assessment requests to remote SSL Labs servers and that this information will be shared with them.

### License

[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

<p align="center"><a href="https://essentialkaos.com"><img src="https://gh.kaos.st/ekgh.svg"/></a></p>
