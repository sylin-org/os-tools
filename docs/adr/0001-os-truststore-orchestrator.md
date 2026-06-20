# ADR 0001 — os-truststore: an orchestrator for the OS trust store

- **Status:** Accepted
- **Date:** 2026-06-19
- **Crate:** `os-truststore` (first member of the `os-tools` family)

## Context

Installing a private/local **CA root** into the operating system's trust store — so the OS
and the tools that trust it accept certificates signed by that CA — is a solved-but-scattered
problem. The mature Rust crates only *read* the system store (`rustls-native-certs`,
`rustls-platform-verifier`); `keyring` covers the *secret* store. There is **no mature,
turnkey Rust crate that writes the trust store** cross-platform. The existing attempts are
unfit to depend on: `ca_injector` (ZeroTier) is archived/Linux-only; `fastcert` is <1yr old
with a single hardcoded cert name and no Alpine/RHEL/openSUSE handling.

The canonical implementations (`mkcert`, `smallstep/truststore`, used by Caddy) are all Go
and BSD-3-Clause. The mechanism is wildly different per platform and **per OS version**:
- **Linux** — no API; write a PEM to a distro-specific anchor dir and run a distro-specific
  refresh tool (`update-ca-certificates` / `update-ca-trust` / `trust`), with silent-ignore
  traps (wrong extension, missing tool on musl/busybox, regenerated bundles).
- **macOS** — `security add-trusted-cert`, but a hard version cliff: root sufficed ≤10.15;
  Big Sur+ forces interactive auth; 14.7.5+/15.x make headless admin-trust effectively
  MDM-only, and the CLI can exit 0 while leaving the cert untrusted.
- **Windows** — CryptoAPI; the legacy `CertOpenSystemStoreW` silently scopes to the *current
  user*, not the machine.

The full prior-art harvest (cited, version-specific, adversarially reviewed) lives in
[../PRIOR-ART.md](../PRIOR-ART.md). This ADR records the resulting design.

## Decision

Ship `os-truststore` as a thin **orchestrator / router**: one symmetric API, with
mirror-not-copy platform implementations underneath — **OS = Operational Symmetry**. We
own only the orchestration (detect → try in order → verify → loud structured failure); we
**delegate** the hard primitives to mature crates (`schannel` on Windows, `rustls` for the
in-process path, `pem`/`x509-parser` for parsing) and to the **OS-native tools** by
shelling out where that is the battle-tested path (Linux refresh tools, macOS `security`).
We learn facts/algorithms from the BSD-3 references and **write our own code**.

### Public API (delight-optimized: least surprise, "just works")

The certificate **is** the identity — no caller-supplied names to invent or track:

```rust
let ca = os_truststore::Cert::from_pem(bytes)?;   // validates "is this a CA?" up front
os_truststore::install(&ca)?;                      // System scope by default
os_truststore::is_installed(&ca)?;
os_truststore::uninstall(&ca)?;                    // Ok even if already absent (idempotent)

os_truststore::Install::new(&ca)                   // builder for the 10%
    .scope(Scope::CurrentUser)
    .label("My Org Root")
    .run()?;
```

- **Identity = SHA-256 of the DER** (filename stem / Windows thumbprint / removal key).
  Never a hardcoded name (that caps you at one CA — fastcert's mistake).
- **Display name auto-derives from the cert CN** so an operator inspecting the store sees a
  sensible name; `.label()` overrides.
- **Idempotent**: re-install → `Ok(Report::AlreadyInstalled)`; uninstall of an absent cert
  → `Ok(())`.
- **Never silently under-deliver**: default scope is `System`; without privilege the call
  returns a typed `NeedsElevation` (with the fix spelled out) — **not** a silent per-user
  fallback. Partial success (macOS) surfaces as `Report::InstalledNotTrusted { reason }`,
  never a lying `Ok`.
- **Typed, actionable errors** (`TrustError`): `NotCaCertificate`, `StoreNotFound`,
  `StoreToolMissing { hint }`, `NeedsElevation`, `InteractiveAuthRequired`,
  `CommandFailed { stderr }`, … — **never panic**.
- **In-process no-admin path** (the `rustls` feature) is first-class: hand back a
  `rustls::RootCertStore` that trusts the CA without touching the OS store — works 100% of
  the time, no elevation. For many callers that *is* "just works".

### Scope decisions (v0.1)

- **System trust store only.** NSS (Firefox/Chrome) and Java are separate stores, proven
  separable; deferred behind opt-in, soft-fail features in a later phase.
- **Privileged write = direct-when-root, else `NeedsElevation`.** No `sudo` shell-out in
  v0.1 (it hard-fails in non-tty daemon/container contexts — the intended runtime is an
  elevated service/daemon). The error names the manual remedy.
- **Honest platform tiers:** Tier 1 (developed + verified) = Windows 11, Debian/Ubuntu;
  Tier 2 (CI-compiled/tested, store mutation not hands-on) = macOS, Fedora/Arch/Alpine;
  Tier 3 (from-reference, needs a live box) = openSUSE (anchor-dir contradiction),
  FreeBSD (out of scope until validated).
- **Architecture:** compile-time `#[cfg(target_os)]` module dispatch; runtime distro
  detection lives only in the Linux module; external tools run as argument vectors, never
  shell strings.

## Consequences

- **Lean core:** the Linux build pulls only `pem`/`x509-parser`/`sha2`/`thiserror`/
  `tracing` (+ `libc`/`which`); `schannel` is Windows-only, `rustls` is feature-gated. The
  "dependency-light" pitch holds.
- **The orchestrator is the value.** If a mature crate did the whole job we wouldn't build
  this; owning the detection/ordering/fallback (built on the OS tools) is the point.
- **Survives the failure mode that killed `ca_injector`:** a living daily consumer (Koi),
  cross-platform completeness as a goal, and honest tiers instead of empty promises.
- **macOS is best-effort by physics, and we say so** (read-back verification +
  `InstalledNotTrusted`/`InteractiveAuthRequired` + MDM signpost), rather than claiming
  silent CI/system trust.
- **Open items** tracked in PRIOR-ART.md (openSUSE dir, p11-kit `trust anchor`, NSS specifics).
