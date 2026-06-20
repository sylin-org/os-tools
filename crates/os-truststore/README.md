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

The certificate **is** the identity — install, query, and remove with the same `Cert`; the
crate derives a stable identity (SHA-256 of the DER) internally. No names to invent.

```rust
let bytes = std::fs::read("my-root-ca.pem")?;
let ca = os_truststore::Cert::from_pem(&bytes)?;   // validates "is this a CA?" up front

os_truststore::install(&ca)?;                        // system store (needs elevation)
assert!(os_truststore::is_installed(&ca)?);
os_truststore::uninstall(&ca)?;                      // Ok even if already absent
```

Options via the builder:

```rust
use os_truststore::{Install, Scope};

Install::new(&ca)
    .scope(Scope::CurrentUser)   // no-elevation per-user install (Windows/macOS)
    .label("My Org Root")        // display name where the platform supports one
    .run()?;
```

- **Idempotent** — re-installing returns `Ok(Report::AlreadyInstalled)`; uninstalling an
  absent cert is `Ok(())`.
- **Never silently under-delivers** — the default scope is `System`; without elevation you
  get a typed `TrustError::NeedsElevation` (with the manual remedy), never a quiet per-user
  install. Partial success on macOS surfaces as `Report::InstalledNotTrusted { reason }`.
- **Typed, actionable errors**, never a panic: `NotCaCertificate`, `StoreNotFound`,
  `StoreToolMissing { hint }`, `NeedsElevation`, `InteractiveAuthRequired`,
  `CommandFailed { stderr }`.

### Trust in-process — no elevation, no OS store (the `rustls` feature)

If you only need *your own* `rustls`/`reqwest` client to trust the CA, skip the OS store
entirely. This works on every platform with no privileges:

```rust
// os-truststore = { version = "0.0.2", features = ["rustls"] }
let roots = os_truststore::inprocess::rustls_root_store(&ca)?;
let config = rustls::ClientConfig::builder()
    .with_root_certificates(roots)
    .with_no_client_auth();
```

For `reqwest`, use its own API directly: `reqwest::Certificate::from_der(ca.der())` then
`ClientBuilder::add_root_certificate(...)`.

## Platform support

`os-truststore` uses an explicit, honest support-tier model — we state what is verified
rather than implying uniform coverage. (Full per-version detail + citations:
[docs/PRIOR-ART.md](https://github.com/sylin-org/os-tools/blob/main/docs/PRIOR-ART.md).)

| Platform | Mechanism | Tier |
| --- | --- | --- |
| Windows (LocalMachine / CurrentUser `ROOT`) | native CryptoAPI via [`schannel`](https://crates.io/crates/schannel) | **1** |
| Linux — Debian/Ubuntu | `/usr/local/share/ca-certificates/` + `update-ca-certificates` | **1** |
| Linux — RHEL/Fedora/CentOS/Rocky/Alma | `/etc/pki/ca-trust/source/anchors/` + `update-ca-trust extract` | **2** |
| Linux — Arch/Manjaro | `/etc/ca-certificates/trust-source/anchors/` + `trust extract-compat` | **2** |
| Linux — Alpine/musl | same as Debian; minimal images without the tool → `StoreToolMissing` | **2** |
| macOS | `security add-trusted-cert` + read-back verification | **2** |
| Linux — openSUSE/SLE | `/etc/pki/trust/anchors/` + `update-ca-certificates` | **3** |

- **Tier 1** — developed on and hands-on verified.
- **Tier 2** — implemented + compiled/tested in CI; real store mutation may need a privileged
  runner.
- **Tier 3** — implemented from the reference, needs hands-on confirmation (openSUSE's admin
  anchor dir is a known reference contradiction — see PRIOR-ART.md).

**Linux detection** reads `/etc/os-release` first, then falls back to directory existence,
so derivatives and minimal containers resolve correctly. The refresh tool must be present
(else a loud `StoreToolMissing` with the install hint) — never a silent no-op.

**macOS reality:** root sufficed for headless trust only through 10.15. Big Sur+ requires
interactive authorization, and 14.7.5+/15.x make unattended admin trust effectively
MDM-only. We add the cert, verify by read-back, and report `InstalledNotTrusted` /
`InteractiveAuthRequired` honestly rather than claiming silent system trust.

> The end-to-end install/remove round-trip mutates the real OS trust store and needs
> elevation, so it is `#[ignore]`-d by default. Run it explicitly on a machine where that
> is safe: `cargo test -p os-truststore -- --ignored`.

## Not in scope (yet)

NSS (Firefox/Chrome) and Java keystores are *separate* trust stores from the OS store.
They are deliberately out of scope for now and will be opt-in, soft-fail backends behind
features in a later release — for machine-to-machine TLS (OpenSSL/rustls/Go) they are not
needed.

## Credit

Approach informed by [mkcert](https://github.com/FiloSottile/mkcert) and
[smallstep/truststore](https://github.com/smallstep/truststore) (the Go reference
implementations). Facts and algorithms were learned from those projects; the code here is
our own. See [docs/PRIOR-ART.md](https://github.com/sylin-org/os-tools/blob/main/docs/PRIOR-ART.md).

## License

Dual-licensed under either of [Apache-2.0](../../LICENSE-APACHE) or
[MIT](../../LICENSE-MIT) at your option.
