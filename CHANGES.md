# Changelog

All notable changes to est_proxy are documented here.

## [0.2.0]

### Added
- RADIUS authentication backend (via `pyrad2`) for basic-auth users, supporting
  both plain **UDP RADIUS** and **RadSec (RADIUS over TLS, RFC 6614)** with
  mutual-TLS client certificates, configurable TLS floor, and server-name /
  hostname verification.
- Per-user `auth_backend` selection (`local` vs `radius`) so credentials can be
  verified locally or delegated to a RADIUS server.
- Database user management: create/update users and update passwords
  (`Database` CRUD), plus a `db_update` maintenance tool. Database schema
  version bumped to 3.
- GitHub Actions release pipeline that builds the Docker image, saves it as a
  compressed tarball, and publishes a GitHub Release on `v*` tags (with
  tag/version.py consistency check).
- CI workflow running the unittest suite on push and pull requests.

### Changed
- Hardened CSR identity binding against injection: CN/DNS/IP set-equality
  checks, SAN type validation, and rejection of unexpected subject attributes
  and extensions.
- Local password handling now uses bcrypt hashes with automatic rehashing of
  legacy sha512 hashes on successful login.
- Tidied comments, hoisted module-level constants (`ALLOWED_SUBJECT_OIDS`,
  `CSR_EXTENSION_NAMES`), and aligned code with house style.
- Substantially expanded the test suite (est_handler, helper, database,
  CSR fixtures).

### Removed
- Bundled CA handlers other than MS-WCCE (certifier, openssl, xca, mscertsrv)
  and their stale CI workflows / test fixtures.

## [0.1.0]

### Added
- Initial EST protocol proxy implementing [RFC 7030](https://tools.ietf.org/html/rfc7030):
  EST server, protocol handler, and TLS secure server.
- EST endpoints: `cacerts`, `simpleenroll`, and `simplereenroll`, including
  chunked transfer-encoding support and PKCS#7 handling.
- Client authentication (`_auth_check`) with basic auth, and SRP / dual
  (client-cert + SRP) authentication support in the TLS handshake (Daemon
  section, patched tlslite-ng).
- Modular CA handler interface with handlers for Microsoft CA, OpenSSL CA,
  XCA, and an insta Certifier handler, plus a skeleton handler for new backends.
- MS-WCCE (Microsoft Windows Client Certificate Enrollment via RPC/DCOM) CA
  handler adopted from acme2certifier.
- Configuration via config file and command line; connection logging;
  base64 URL encode/decode helpers.
- SQLite database for tracking issued certificates; CA template lookup per
  authenticated user.
- Per-user regex checks on the CSR common name, and CSR/certificate validation
  (SAN handling, other-SAN detection, reenrollment identity checks).
- Docker image with example configuration and documentation.
