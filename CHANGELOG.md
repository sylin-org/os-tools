# Changelog

All notable changes to the `os-tools` family are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crates follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned (os-truststore)

- **Linux, exhaustively**: p11-kit `trust anchor`, RHEL/Fedora `update-ca-trust`, Arch
  `trust extract-compat`, openSUSE, and a busybox/musl consolidated-bundle fallback — with
  a loud, structured error when no install method is available (never a silent no-op).
- **Windows native**: `schannel` API in place of shelling out to `certutil`.
- **In-process trust** (`rustls` feature): a `rustls` `RootCertStore` / `reqwest` client
  that trusts a CA without touching the OS store — the privilege-free floor.
- **NSS / Java** keystores behind optional features.

## [0.1.0] — unreleased

### Added

- `os-truststore` — one symmetric API for installing and removing a CA certificate in the
  operating system's trust store (`install_ca_cert`, `remove_ca_cert`, `is_ca_installed`,
  `parse_ca_cert`). Windows (`certutil`), macOS (`security`, System keychain), and Linux
  (Debian/Ubuntu: `/usr/local/share/ca-certificates` + `update-ca-certificates`).
- Strict certificate-name validation and CA-basic-constraint validation (refuses to
  install a non-CA / leaf certificate as a root).
- Dual Apache-2.0 OR MIT licensing; CI across Windows, macOS, and Linux.

[Unreleased]: https://github.com/sylin-org/os-tools/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sylin-org/os-tools/releases/tag/v0.1.0
