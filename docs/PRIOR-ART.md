# Trust-store prior art & lessons learned

This is the aggregated, cross-checked knowledge base behind `os-truststore` — what every
serious "install a CA root into the OS trust store" implementation has learned, across
implementations, operating systems, and **their versions**. It is the spec source for the
`os-truststore` orchestrator.

**How this was built, and the rule we follow.** The facts below were harvested by reading
the real source of the canonical implementations and the authoritative OS/distro docs,
then verified by an adversarial review pass. The references are all BSD-3-Clause; we
**learn the facts and algorithms (which are not copyrightable) and write our own code** —
we do not copy source. Where our conclusion *corrects* a reference, it is called out.

**Credit (approach informed by):** [mkcert](https://github.com/FiloSottile/mkcert) and
[smallstep/truststore](https://github.com/smallstep/truststore) (the Go gold standard,
also used by Caddy), [fastcert](https://github.com/ozankasikci/fastcert) and the archived
[ca_injector](https://github.com/zerotier/ca_injector) (Rust attempts),
[devcert](https://github.com/davewasmer/devcert) (Node, for the Firefox/NSS/WSL lessons),
and the distro/OS documentation cited per row.

---

## TL;DR — the rules that bite every implementation

1. **Read (`is_installed`) and write (`install`) are different mechanisms.** Never reuse
   one for the other, and never rely on a process-cached system trust pool to check
   presence — a freshly installed cert reads "not installed" until the next process
   (golang/go#24540). Use per-store **native** queries.
2. **Idempotency is mandatory and store-specific.** Windows: `CERT_STORE_ADD_REPLACE_EXISTING`.
   NSS/Java: delete-then-add (a duplicate nickname/alias *errors*). Linux: overwrite the
   same stem file. Uninstall must treat *not-found* as success, not an error.
3. **Identity must be derived from the cert, never a hardcoded name.** Use the SHA-256 of
   the DER (or CN+serial) for the filename stem / NSS nickname / Java alias / removal key.
   A single hardcoded name caps the crate at one managed CA (fastcert's mistake).
4. **Format and extension are load-bearing, and failures are SILENT.** Debian/Ubuntu/Alpine
   ignore anything that isn't `.crt` (a `.pem` or DER is silently untrusted); Windows
   CryptoAPI needs DER; the consolidated bundles and `/etc/ssl/certs` hash symlinks are
   *regenerated* — appending or hand-symlinking is silently clobbered. **Never trust a
   tool's exit code alone; verify the cert actually appears.**
5. **Elevation is per-store and never in-process.** Escalate only the system-store
   write/refresh — never user-owned NSS/Java keystores (root corrupts ownership). No OS
   offers in-process self-elevation: Windows LocalMachine and macOS admin-domain both
   require an already-elevated (and, on modern macOS, *interactive*) context.
6. **Container/daemon/systemd reality breaks naive `sudo`.** Containers run as root with
   **no `sudo` installed**; systemd services have **no TTY** so `sudo`/askpass prompts
   hard-fail; headless `certutil -N` can deadlock on `/dev/tty`. Rule: `uid==0` → run
   directly; else `sudo`+TTY/askpass present → `sudo`; else return `NeedsElevation`.
7. **NSS and Java are SEPARATE trust stores, in both directions.** Firefox (all OSes) and
   Chrome/Chromium-on-Linux ignore the OS store; NSS/Java success does not imply system
   success. For machine-to-machine TLS (OpenSSL/rustls/Go) they are irrelevant — gate them
   behind opt-in flags that **soft-fail**.
8. **Run external tools as argument vectors, never shell strings**; capture stderr into
   typed errors; prefer native APIs (Windows CryptoAPI via `schannel`/`windows-rs`, macOS
   `security-framework`) where a binding exists; **never panic** — let callers
   warn-and-continue (Caddy's hard-won lesson).

---

## Platform matrix (OS × version × mechanism)

### Linux — pick the writable admin anchor dir, then run its refresh tool

Detection order: read `/etc/os-release` `ID`/`ID_LIKE` **first**, then confirm/fallback by
directory existence (this fixes Alpine-misclassified-as-Debian and the openSUSE-vs-RHEL
`/etc/pki` ambiguity).

| Family | Anchor dir | Ext | Refresh | Key quirks |
| --- | --- | --- | --- | --- |
| Debian / Ubuntu / WSL | `/usr/local/share/ca-certificates/` | **`.crt`** (load-bearing) | `update-ca-certificates` | `.pem`/DER is **silently ignored**; one cert per file; `/etc/ssl/certs/ca-certificates.crt` is regenerated (never append); stale symlinks need `-f`. |
| Alpine / musl | `/usr/local/share/ca-certificates/` | `.crt` | `update-ca-certificates` | **Trap:** minimal images ship only `ca-certificates-bundle` — **no** `update-ca-certificates` binary and **no** anchor dir. Dir-existence misdetects; *binary*-existence is the real check → `StoreToolMissing{hint:"apk add ca-certificates"}`. |
| RHEL / Fedora / CentOS / Rocky / Alma | `/etc/pki/ca-trust/source/anchors/` | `.pem` or `.crt` | `update-ca-trust extract` | Accepts PEM **or** DER by content; output regenerated under `/etc/pki/ca-trust/extracted/` (never write there); **must** run extract or nothing takes effect. EL6 shipped the store *disabled* (one-time `update-ca-trust enable`) — EL6 is EOL, treat as out of scope. |
| Arch / Manjaro / Artix | `/etc/ca-certificates/trust-source/anchors/` | `.crt` | `trust extract-compat` | p11-kit accepts `.pem`/`.crt`/`.der` by **content**. Cleaner one-step path: `trust anchor --store <cert>` (writes anchor + re-extracts). NB: `update-ca-trust` **does** exist on Arch — preferring `trust` is a tooling convention, not an availability fact. |
| openSUSE / SLE | `/etc/pki/trust/anchors/` ⚠️ | `.pem` | `update-ca-certificates` (a p11-kit wrapper) | **⚠️ Correction + open question:** mkcert/smallstep/fastcert point at `/usr/share/pki/trust/anchors`, which is the **lower-priority vendor dir** (and openSUSE's man page even names it `/usr/share/pki/anchors`, no `trust/`). The admin dir is `/etc/pki/trust/anchors`. **Must be verified on a live box before shipping** — biggest correction risk in this doc. |
| FreeBSD | `/usr/local/etc/ssl/certs/` | **`.pem`** | `certctl rehash` | Single-sourced (smallstep only); modern `certctl` **rejects non-`.pem`**. Out of scope for Phase 1 unless validated on a live host. |

The bare consolidated bundle (`/etc/ssl/certs/ca-certificates.crt`,
`/etc/pki/tls/certs/ca-bundle.crt`) and the `/etc/ssl/certs` hash symlinks are
**regenerated/clobbered** by the refresh tool (`openssl rehash`/`c_rehash` delete all hash
symlinks first) — appending is folklore, not a fallback. The only honest no-tool fallback
is a loud `StoreToolMissing` error with remediation.

### macOS — the version cliff

| Version band | Mechanism | Reality |
| --- | --- | --- |
| ≤ 10.15 (Catalina/Mojave) | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain <cert>` | Running as **root was sufficient** for headless admin-domain trust. Adding to a keychain and *trusting* are separate ops. |
| 11 Big Sur → 15 Sequoia | same command | **Root is no longer sufficient.** Big Sur added a mandatory interactive admin-auth GUI prompt (fails headless/CI/SSH). 14.7.5+: `SecTrustSettingsSetTrustSettings` → `errAuthorizationInteractionNotAllowed`. 15.5: even the old `security authorizationdb` escape hatch → `errAuthorizationDenied`. The CLI can **exit 0 yet leave the cert untrusted** → verify by read-back. Per Apple DTS, the **only** supported headless/enterprise path is an MDM `com.apple.security.root` configuration profile. |

> A single unofficial report (Apple forum 692105) claims Monterey 12.0.1 briefly relaxed
> the prompt for root daemons. Unconfirmed by Apple, no known re-tighten build — **do not
> version-band it in code.** Keep the blanket "best-effort/interactive on 11+, MDM-only
> headless on 14.7.5+/15.x" and always verify by read-back.

So macOS ships as **honest degradation**: add to the keychain (always works), attempt
trust, verify, and on any non-success return `InstalledNotTrusted` + `InteractiveAuthRequired`
rather than claiming silent system trust.

### Windows — scope is the footgun

| Scope | Mechanism | Elevation | Notes |
| --- | --- | --- | --- |
| CurrentUser `ROOT` | `CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0,0, CERT_SYSTEM_STORE_CURRENT_USER, "ROOT")` + `CertAddEncodedCertificateToStore(..., CERT_STORE_ADD_REPLACE_EXISTING=3)` | none | **Footgun:** mkcert/fastcert use legacy `CertOpenSystemStoreW(0,"ROOT")`, which silently opens *this* (per-user) store — a "machine-wide" intent silently scopes to one user. |
| LocalMachine `ROOT` | same, `CERT_SYSTEM_STORE_LOCAL_MACHINE` | **required** | Lands in the `.Default` physical store. **Never** target `.GroupPolicy`/`.Enterprise` (overwritten on policy refresh). No self-elevation; non-elevated → access-denied. |

Input **must be DER** (decode PEM first). The "installing a certificate from a CA…" GUI
warning fires only on the interactive `certmgr`/double-click path, **not** on programmatic
`CertAdd*`. `is_installed`/remove = `CertEnumCertificatesInStore` over the logical Root,
match by **SHA-256 thumbprint**, `CertDuplicateCertificateContext` the match **before**
`CertDeleteCertificateFromStore` (deleting a live enum context invalidates iteration).
Enum-end sentinel = `0x80092004` (`CRYPT_E_NOT_FOUND`).

**Corrected error codes:** `0x80092004` = `CRYPT_E_NOT_FOUND` (the enum sentinel ✓), but
`0x80092003` is `CRYPT_E_FILE_ERROR`, **not** access-denied. Access-denied surfaces as
`E_ACCESSDENIED` (`0x80070005`) / Win32 `ERROR_ACCESS_DENIED` (5). NSS is **not** attempted
on Windows (the built-in `certutil.exe` is a different Microsoft tool; Firefox-on-Windows
is documented as manual).

---

## The exhaust-all-methods chains (the orchestrator's routing)

### Linux
0. **Identity + privilege precompute:** stem = lowercased hex SHA-256 of DER; detect
   `euid==0`, locate `sudo`, detect TTY/askpass; WSL (`/proc/version` ~ `microsoft`) →
   proceed as the underlying distro.
1. **Distro dispatch:** `/etc/os-release` first, dir-existence fallback → `(anchor_dir,
   ext, refresh_argv)`. None resolve → `StoreNotFound`.
2. **Tool-present check (busybox/musl):** the refresh *binary* must exist, not just the
   dir → else `StoreToolMissing{hint}`. (Do not auto-mutate the system in Phase 1.)
3. **Write:** DER→PEM, force the table's extension, one cert per file, `<stem>.<ext>`.
   Direct write when `euid==0`; else `sudo tee` only when `sudo`+TTY present; else
   `NeedsElevation`.
4. **Refresh (mandatory):** run `refresh_argv` as a vector, elevated by the same rule.
   Never append to the bundle / hand-craft symlinks.
5. **Verify:** file-presence in the anchor dir (cheap) and/or membership in the regenerated
   bundle — never trust the exit code alone.
6. **Loud failure:** structured, recoverable error with the on-disk cert path + exact
   manual remediation. Never silently no-op.
   *(Optional, not Phase-1: `trust anchor --store` on p11-kit distros; NSS/Java behind opt-in flags.)*

### macOS
0. Precompute version + GUI availability (sets the honesty expectation).
1. Add to `/Library/Keychains/System.keychain` (always works; storage ≠ trust).
2. Attempt `security add-trusted-cert -d -r trustRoot -k …`.
3. **Verify by read-back** (`security-framework` TrustSettings / `security verify-cert`) —
   do not trust exit 0.
4. Classify any non-success → `InteractiveAuthRequired`, return `InstalledNotTrusted`.
5. Loud failure / MDM signpost (`com.apple.security.root` `.mobileconfig`).

### Windows
0. Scope decision (default LocalMachine for a "CA root"); SHA-256 identity; DER-decode up front.
1. `CertOpenStore` with the explicit scope (**not** `CertOpenSystemStoreW`).
2. LocalMachine + access-denied → `NeedsElevation` (no self-elevation).
3. `CertAddEncodedCertificateToStore(..., REPLACE_EXISTING=3)` into logical Root (`.Default`).
4. `is_installed`/remove by enumeration + SHA-256 thumbprint; duplicate-context before delete.
5. WSL → run the Linux chain (separate trust domain).
6. Loud, structured failure on any unhandled HRESULT.

---

## Open questions (need a live box before those rows are promoted past Tier 3)

- **openSUSE anchor dir** — `/etc/pki/trust/anchors` (our corrected admin dir) vs the
  references' `/usr/share/pki/trust/anchors` vs openSUSE man's `/usr/share/pki/anchors`,
  and `.pem` vs `.crt`. *Biggest risk.* Verify on Tumbleweed/Leap/SLE.
- **macOS 12.x daemon relaxation** — confirm/deny on a real Monterey box; until then,
  unbanded.
- **p11-kit `trust anchor --store` in Phase 1** — cleaner on RHEL/Arch/openSUSE but absent
  on Debian/Alpine and doesn't pin a deterministic file path for `is_installed`. Decision +
  live test of the "no configured writable location" fallback.
- **`is_ca_installed` depth on Linux** — file-presence vs verify-against-pool (Caddy's
  pattern); validate it avoids the Go process-cache staleness.
- **Privileged-write strategy** — `sudo tee` (CLI-friendly, daemon-hostile) vs
  direct-write-when-root-only. Product decision tied to the intended runtime.
- **FreeBSD** — single-sourced, `.pem` not `.crt`; validate or declare out of scope.
- **NSS specifics** (cert8 `dbm:` prefix, Chromium ≥M146 XDG nssdb path) — Phase-2/NSS scope.

---

*Maintained alongside `os-truststore`. When a row is verified hands-on, move it out of Open
Questions and note the verification in the row.*
