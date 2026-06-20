# os-tools

**OS = Operational Symmetry.** One identical API; implementations that are mirrors, not
copies — *structurally symmetric, mechanically alien.*

`os-tools` is a family of small, dependency-light Rust crates that each present **one
symmetric API** over the wildly different platform-native mechanisms underneath. Every
crate does the same job the same way on every OS; only the machinery behind the surface
changes — Windows one way, macOS another, Linux a third.

## Crates

| Crate | What it does | Status |
| --- | --- | --- |
| [`os-truststore`](crates/os-truststore) | Install / remove a CA certificate in the OS trust store. To the **trust** store what [`keyring`](https://crates.io/crates/keyring) is to the **secret** store — the missing symmetric *writer*. | `0.0.1` |

## Why

Every OS guards trust differently — `certutil` and the Windows certificate store, the
macOS Keychain via `security`, and on Linux a thicket of `update-ca-certificates` /
`update-ca-trust` / `trust` / p11-kit. The mature crates in this space only *read* the
system trust store ([`rustls-native-certs`](https://crates.io/crates/rustls-native-certs),
`rustls-platform-verifier`); the symmetric *writer* — "install this root, everywhere, the
same way" — has been missing. `os-tools` fills these corners one symmetric surface at a
time.

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual-licensed as above, without any additional terms or conditions.
