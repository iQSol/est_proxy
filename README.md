<!-- markdownlint-disable  MD013 -->
# est_proxy

est_proxy is development project to create an est protocol proxy. Main
intention is to provide est enrollment services on CA servers which do not support this
protocol. This fork focused specifically on Windows CAs. It consists of two libraries:

- est_proxy/*.py - a bunch of classes implementing est server functionality based
on [rfc7030](https://tools.ietf.org/html/rfc7030)
- ca_handler.py - interface towards CA server. The intention of this library
is to be modular that an [adaption to other CA servers](docs/ca_handler.md)
should be straight forward.

As of today the following handler is maintained:
  - [Microsoft Windows Client Certificate Enrollment Protocol (MS-WCCE) via RPC/DCOM](examples/est_proxy.cfg)

Other handles are available, but are not maintained:
  - [NetGuard Certificate Manager/Insta certifier](docs/certifier.md)
  - [Openssl](docs/openssl.md)
  - [XCA](docs/xca.md)


To build your own container navigate to the folder `examples/Docker` and execute following command:

```
docker-compose build --no-cache
```

> [!WARNING]
> The EST proxy has to run behind nginx. Otherwise you will have security problems.

Therefore, you should use the following Nginx configuration:
```nginx
server {
		listen <ip-address>:9443 ssl default_server;

		ssl_certificate         path/to/est-srv.crt.pem;
		ssl_certificate_key     path/to/est-srv.key.pem;
		ssl_client_certificate  path/to/ca-certs.pem;
		ssl_verify_client optional;

		server_name _;

		location / {
			proxy_pass https://127.0.0.1:9443;
			proxy_set_header Host $host;
			proxy_set_header X-Real-IP $remote_addr;
			proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
			proxy_set_header X-Forwarded-Proto $scheme;
			proxy_set_header X-SSL-Verified $ssl_client_verify;
			proxy_set_header X-CLIENT-Cert $ssl_client_cert;
		}

		if ($request_method !~ ^(GET|HEAD|POST)$ )
		{
				return 405;
		}
}
```


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
