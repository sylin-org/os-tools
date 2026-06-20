# os-truststore

[![Crates.io](https://img.shields.io/crates/v/os-truststore.svg)](https://crates.io/crates/os-truststore)
[![Docs.rs](https://docs.rs/os-truststore/badge.svg)](https://docs.rs/os-truststore)
[![License](https://img.shields.io/crates/l/os-truststore.svg)](https://github.com/sylin-org/os-tools#license)

**One symmetric API for the operating system's trust store.** Install and remove a CA
certificate so the OS — and the applications and tools that trust it — accept certificates
signed by that CA, on Windows, macOS, and Linux.

Part of the [`os-tools`](https://github.com/sylin-org/os-tools) family. **OS = Operational
Symmetry**: the API is identical on every platform; the implementations are mirrors, not
copies — structurally symmetric, mechanically alien.

## Where it fits

- [`rustls-native-certs`](https://crates.io/crates/rustls-native-certs) /
  [`rustls-platform-verifier`](https://crates.io/crates/rustls-platform-verifier) — *read*
  the system trust store (for use as a TLS client).
- [`keyring`](https://crates.io/crates/keyring) — a symmetric API over the *secret* store
  (Credential Manager / Keychain / Secret Service).
- **`os-truststore`** — the missing corner: a symmetric API that *writes* the *trust*
  store.

## Usage

```rust
let pem = std::fs::read_to_string("my-root-ca.pem")?;

// Validates that the PEM is actually a CA certificate (rejects a leaf/server cert).
let parsed = os_truststore::parse_ca_cert(&pem)?;

// Installing into the system trust store requires elevated privileges.
os_truststore::install_ca_cert(&parsed.pem, "my-org-root")?;

assert!(os_truststore::is_ca_installed("my-org-root"));

os_truststore::remove_ca_cert("my-org-root")?;
```

Installing into the **system** trust store requires elevated privileges (Administrator /
`sudo` / admin). Errors are **returned, never panicked** — a caller can warn and continue
when the store cannot be modified.

## Platform support

`os-truststore` uses an explicit, honest support-tier model — we state what is verified
rather than implying uniform coverage.

| Platform | Mechanism | Tier |
| --- | --- | --- |
| Windows 11 | `certutil -addstore Root` | **1** — developed on + hands-on verified |
| Linux (Debian / Ubuntu) | `/usr/local/share/ca-certificates/` + `update-ca-certificates` | **1** — developed on + hands-on verified |
| macOS | `security add-trusted-cert` (System keychain) | **2** — compiles + unit-tested in CI; store mutation not yet hands-on verified |
| Other Linux (RHEL/Fedora, Arch, openSUSE, Alpine) | *see roadmap* | **3** — planned (from the mkcert / `smallstep/truststore` reference) |

- **Tier 1** — developed on and verified by hand; gated in CI.
- **Tier 2** — compiles and unit-tests in CI; real store mutation (which needs elevation)
  is not yet automatically exercised.
- **Tier 3** — planned / implemented from a reference algorithm, community-verified.

> The end-to-end install/remove round-trip mutates the real OS trust store and needs
> elevation, so it is `#[ignore]`-d by default. Run it explicitly on a machine where that
> is safe: `cargo test -p os-truststore -- --ignored`.

## Roadmap

`os-truststore` is `0.1.0` — the cross-platform surface is in place; breadth lands next
(tracked in [CHANGELOG](../../CHANGELOG.md)):

- **Linux, exhaustively** — p11-kit `trust anchor`, RHEL/Fedora `update-ca-trust`, Arch
  `trust extract-compat`, openSUSE, and a busybox/musl consolidated-bundle fallback, with
  a loud structured error when no method is available (never a silent no-op).
- **Windows native** — the `schannel` API in place of shelling out to `certutil`.
- **In-process trust** (`rustls` feature) — hand back a `rustls` `RootCertStore` /
  `reqwest` client that trusts a CA without touching the OS store: the privilege-free floor
  for clients you control.
- **NSS / Java** keystores behind optional features.

## License

Dual-licensed under either of [Apache-2.0](../../LICENSE-APACHE) or
[MIT](../../LICENSE-MIT) at your option.
