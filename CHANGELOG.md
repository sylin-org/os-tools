# Changelog

All notable changes to the `os-tools` family are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crates follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.2] — 2026-06-20

First **published** crates.io release. (0.0.1 was tagged but its publish was blocked by the
macOS CI hang fixed below.)

### Fixed

- **MSRV** is declared as **1.88** — bounded by the transitive `time` crate (via
  `x509-parser`); 0.0.1's declared 1.78 was incorrect.
- **macOS** — every `security` call (install, uninstall, and the `find-certificate` read)
  is now time-bounded (10s): a headless trust-authorization prompt returns
  `InteractiveAuthRequired` (or a best-effort `Ok(false)` for the read) instead of hanging
  forever. This is what stalled the 0.0.1 release.
- dependabot no longer chases the intentional `dtolnay/rust-toolchain` MSRV pin.

## [0.0.1] — 2026-06-19

Initial tag — superseded by 0.0.2 (its publish was blocked by the macOS CI hang). Roadmap —
NSS/Java backends, p11-kit `trust anchor`, openSUSE/FreeBSD verification — is tracked in
[docs/PRIOR-ART.md](docs/PRIOR-ART.md) and the [ADR](docs/adr/0001-os-truststore-orchestrator.md).

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

[0.0.2]: https://github.com/sylin-org/os-tools/releases/tag/v0.0.2
[0.0.1]: https://github.com/sylin-org/os-tools/releases/tag/v0.0.1
