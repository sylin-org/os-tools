# Changelog

All notable changes to the `os-tools` family are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crates follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned (os-truststore)

- **NSS** (Firefox/Chrome) and **Java** keystores as opt-in, soft-fail backends behind
  features.
- p11-kit `trust anchor --store` as an alternative one-step Linux path.
- Hands-on verification of the openSUSE anchor dir and FreeBSD support (see PRIOR-ART.md).

## [0.0.1] — 2026-06-19

### Added

- `os-truststore` — one symmetric API (an orchestrator/router) for installing and removing
  a CA certificate in the operating system's trust store, across Windows, macOS, and Linux.
  **OS = Operational Symmetry.**
  - **API:** the certificate is the identity — `Cert::from_pem`/`from_der` (validates the
    cert is a CA), then `install` / `is_installed` / `uninstall` (+ the `Install` builder
    for `scope` and `label`). Idempotent; typed `TrustError`; never panics.
  - **Linux** — exhaust-all-methods orchestrator: `/etc/os-release`-first distro detection
    (Debian/Ubuntu, RHEL/Fedora, Arch, openSUSE, Alpine) with directory-existence fallback,
    the matching refresh tool, a loud `StoreToolMissing` on minimal/musl images, and
    read-back verification — never a silent no-op.
  - **Windows** — native CryptoAPI via `schannel` with explicit `LocalMachine`/`CurrentUser`
    scope (no `certutil` subprocess; no silent current-user footgun); idempotent
    `ReplaceExisting`; `NeedsElevation` when not elevated.
  - **macOS** — `security` with honest degradation: add → verify by read-back → report
    `InstalledNotTrusted` / `InteractiveAuthRequired` rather than claiming silent trust on
    Big Sur+/Sequoia.
  - **In-process trust** (`rustls` feature) — `inprocess::rustls_root_store` builds a
    `rustls::RootCertStore` that trusts the CA with no OS store and no elevation.
- Dual Apache-2.0 OR MIT licensing; CI across Windows, macOS, and Linux + MSRV check.
- [docs/PRIOR-ART.md](docs/PRIOR-ART.md): cited, version-specific, adversarially-reviewed
  prior-art harvest behind the design; [docs/adr/0001-os-truststore-orchestrator.md](docs/adr/0001-os-truststore-orchestrator.md).

[Unreleased]: https://github.com/sylin-org/os-tools/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/sylin-org/os-tools/releases/tag/v0.0.1
