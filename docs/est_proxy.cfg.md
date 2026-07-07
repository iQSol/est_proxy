<!-- markdownlint-disable  MD013 -->
<!-- wiki-title Configuration options for est_proxy -->
# est_proxy configuration

est_proxy will be configured by a global configuration which needs to be specified when starting the proxy.

```bash
grindsa@rlh:~# est_proxy -c  est_proxy.cfg
```

## configuration options for est_proxy

| Section | Option | Description | Values | default|
| :-------| :------| :-----------| :------| :------|
| `DEFAULT` | `debug`  | Debug mode| True/False| False|
| `Daemon` | `address` | listing IP of est_proxy | True/False | None|
| `Daemon` | `port` | listening port of est_proxy  | integer | 1443|
| `Daemon` | `key_file` | key file in pem format   | True/False | None|
| `Daemon` | `cert_file` | certifcate file in pem format  | Integer  |None |
| `CAhandler` | `handler_file` | path and name of ca_handler file to be loaded. If not specified `est_proxy/ca_handler.py` will be loaded | examples/ca_handler/mswcce_ca_handler.py | `est_proxy/ca_handler.py`|
| `Logging` | `log_format` | logging formatter | [logging.Formatter](https://docs.python.org/3/library/logging.html#logging.Formatter) | `'%(message)s'`|
| `RADIUS` | `enabled` | explicit switch to turn RADIUS off without removing the section; missing or empty counts as enabled | True/False | True|
| `RADIUS` | `server` | ip/dns name of the RADIUS server | string | None|
| `RADIUS` | `proto` | transport: `udp` (plain RADIUS) or `radsec` (RADIUS over TLS, RFC 6614) | udp/radsec | udp|
| `RADIUS` | `secret` | RADIUS shared secret (required for `udp`; optional for `radsec` — defaults to the RFC 6614 value `radsec`) | string | None (udp) / radsec (radsec)|
| `RADIUS` | `port` | RADIUS authentication port | integer | 1812 (udp) / 2083 (radsec)|
| `RADIUS` | `timeout` | RADIUS request timeout in seconds | integer | 5|
| `RADIUS` | `retries` | number of RADIUS request retries (udp only) | integer | 1|
| `RADIUS` | `nas_identifier` | value sent as the NAS-Identifier attribute | string | est_proxy|
| `RADIUS` | `certfile_server` | CA used to verify the RADIUS server certificate (radsec) | path | None|
| `RADIUS` | `certfile` | client certificate presented to the RADIUS server (radsec, mutual TLS) | path | None|
| `RADIUS` | `keyfile` | private key for `certfile` (radsec) | path | None|
| `RADIUS` | `check_hostname` | verify the RADIUS server certificate hostname (radsec); set `False` for lab/testing | True/False | True|
| `RADIUS` | `min_tls_version` | lowest TLS version to negotiate (radsec): `1.3`, `1.2` for legacy servers, or `1.1` (deprecated, RFC 8996 — opt-in only) | 1.1/1.2/1.3 | 1.3|

The daemon listener negotiates TLS 1.2 or higher (RFC 7030 requires at least TLS 1.1). Client certificates are not verified by the daemon itself — certificate authentication is delegated to nginx (see the [README](../README.md) for the required configuration).

The options for the `CAHandler` section depend on the CA handler.

The `RADIUS` section is only needed for basic-auth users provisioned with `auth_backend='radius'` (via `Database.insert_or_update_user()`). Users with `auth_backend='local'` (the default) keep authenticating against their locally stored password hash regardless of whether `RADIUS` is configured. If a `radius` user authenticates while the `RADIUS` section is disabled/missing/incomplete, or the RADIUS server is unreachable, authentication fails (est_proxy does not fall back to the local password check). Option values left empty are treated as unset, so configuration templates can ship every key as a blank line.

est_proxy uses the [`pyrad2`](https://pypi.org/project/pyrad2/) library for RADIUS. With `proto = radsec`, it connects to the RADIUS server over TLS (TCP, default port 2083) with mutual authentication: it presents `certfile`/`keyfile` as the client certificate and verifies the server against `certfile_server`. The shared secret defaults to `radsec` per RFC 6614; set `secret` only if your server expects a non-default value. RadSec negotiates TLS 1.3 by default (`min_tls_version = 1.2` bridges legacy servers; `1.1` is deprecated per RFC 8996 and should only be used as a last resort). This protects the PAP password with real transport encryption instead of RADIUS's weak shared-secret obfuscation.

The optional `CSRvalidation` section controls which X.509v3 extensions a CSR may carry. `subjectAltName` is always validated and forwarded; every other extension is rejected unless listed in `allowed_extensions` (comma-separated, case-insensitive names or dotted OIDs). The default is `keyUsage, extendedKeyUsage, basicConstraints` — extensions a Microsoft AD CS template overrides from the CSR anyway, so clients such as FortiGate that add them by default are not rejected.

> **Do not add `certificatePolicies`** unless you have verified your CA strips it. An MS-WCCE CA copies `certificatePolicies` from the CSR verbatim — including `anyPolicy` and attacker-controlled CPS/userNotice qualifiers — so allowing it lets an authenticated client inject arbitrary policy assertions into the issued certificate.

Besides the common name (validated against the user's `common_name_regex`), a CSR subject may carry `O`, `OU`, `C`, `L` and `ST` attributes with any value on enrollment — they are passed to the CA verbatim. Any other subject attribute type (`emailAddress`, `serialNumber`, `DC`, ...) is rejected. On reenroll (client certificate presented), the CSR subject must additionally match the subject of the presented client certificate exactly.

See [examples/est_proxy.cfg](../examples/est_proxy.cfg) for a MS-WCCE handler configuration example.
