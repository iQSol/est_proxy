<!-- markdownlint-disable  MD013 -->
# est_proxy

est_proxy is development project to create an est protocol proxy. Main
intention is to provide est enrollment services on CA servers which do not support this
protocol. It consists of two libraries:

- est_proxy/*.py - a bunch of classes implementing est server functionality based
on [rfc7030](https://tools.ietf.org/html/rfc7030)
- ca_handler.py - interface towards CA server. The intention of this library
is to be modular that an [adaption to other CA servers](docs/ca_handler.md)
should be straight forward. As of today the following handlers are available:
  - [NetGuard Certificate Manager/Insta certifier](docs/certifier.md)
  - [Microsoft Certificate Enrollment Web Services](docs/mscertsrv.md)
  - [Openssl](docs/openssl.md)
  - [XCA](docs/xca.md)


## Contributing

Please read [CONTRIBUTING.md](docs/CONTRIBUTING.md) for details on my code of
conduct, and the process for submitting pull requests.
Please note that I have a life besides programming. Thus, expect a delay
in answering.

## Versioning

I use [SemVer](http://semver.org/) for versioning. For the versions available,
see the [tags on this repository](https://github.com/grindsa/dkb-robo/tags).

## License

This project is licensed under the GPLv3 - see the [LICENSE](LICENSE) file for details
