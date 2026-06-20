//! `os-truststore` — one symmetric API for the operating system's trust store.
//!
//! **OS = Operational Symmetry.** Install and remove a CA certificate in the platform
//! trust store so the OS — and the applications and tools that trust it — accept
//! certificates signed by that CA. The API is identical on every platform; the
//! implementations are mirrors, not copies.
//!
//! The certificate **is** the identity — you install, query, and remove with the same
//! [`Cert`], and the crate derives a stable identity (SHA-256 of the DER) internally. No
//! names to invent or track.
//!
//! ```no_run
//! let bytes = std::fs::read("my-root-ca.pem")?;
//! let ca = os_truststore::Cert::from_pem(&bytes)?;   // validates "is this a CA?"
//!
//! os_truststore::install(&ca)?;                        // system store; needs elevation
//! assert!(os_truststore::is_installed(&ca)?);
//! os_truststore::uninstall(&ca)?;                      // Ok even if already absent
//! # Ok::<(), os_truststore::TrustError>(())
//! ```
//!
//! Installing into the **system** store needs elevation; without it you get a typed
//! [`TrustError::NeedsElevation`] (never a silent narrower install). If you only need
//! *your own* `rustls`/`reqwest` client to trust the CA — no elevation, no OS store, works
//! everywhere — enable the `rustls` feature and use the `inprocess` module.

mod cert;
mod detect;
mod error;

#[cfg(feature = "rustls")]
pub mod inprocess;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod darwin;

#[cfg(windows)]
mod windows;

pub use cert::Cert;
pub use error::{Result, TrustError};

/// Which trust store to target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Scope {
    /// The machine-wide system store (default). Requires elevation to modify.
    #[default]
    System,
    /// The current user's store (no elevation): the CurrentUser `ROOT` store on Windows,
    /// the login keychain on macOS. On Linux there is no per-user system trust store, so
    /// this behaves the same as [`Scope::System`]; use the `inprocess` module for
    /// per-process trust without privileges.
    CurrentUser,
}

/// The outcome of a successful install.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Report {
    /// The certificate was installed.
    Installed,
    /// The certificate was already present — nothing to do (idempotent).
    AlreadyInstalled,
    /// The certificate was added to the store, but trust could not be confirmed (macOS:
    /// admin-domain trust needs interactive authorization). `reason` explains.
    InstalledNotTrusted {
        /// Why trust could not be confirmed.
        reason: String,
    },
}

/// Install `cert` into the system trust store (the common case).
///
/// Idempotent. Requires elevation; returns [`TrustError::NeedsElevation`] otherwise. For
/// options (scope, display label) use [`Install`].
pub fn install(cert: &Cert) -> Result<Report> {
    Install::new(cert).run()
}

/// Remove `cert` from the system trust store. `Ok(())` even if it was not present.
pub fn uninstall(cert: &Cert) -> Result<()> {
    dispatch_uninstall(cert, Scope::System)
}

/// Whether `cert` is present in the system trust store.
pub fn is_installed(cert: &Cert) -> Result<bool> {
    dispatch_is_installed(cert, Scope::System)
}

/// Builder for [`install`] with options.
///
/// ```no_run
/// # let ca = os_truststore::Cert::from_pem(b"").unwrap();
/// os_truststore::Install::new(&ca)
///     .scope(os_truststore::Scope::CurrentUser)  // no-elevation per-user (Windows/macOS)
///     .label("My Org Root")                      // display name where supported
///     .run()?;
/// # Ok::<(), os_truststore::TrustError>(())
/// ```
#[derive(Debug, Clone)]
pub struct Install<'a> {
    cert: &'a Cert,
    scope: Scope,
    label: Option<String>,
}

impl<'a> Install<'a> {
    /// Start an install of `cert` (system scope by default).
    pub fn new(cert: &'a Cert) -> Self {
        Self {
            cert,
            scope: Scope::System,
            label: None,
        }
    }

    /// Target a specific [`Scope`].
    pub fn scope(mut self, scope: Scope) -> Self {
        self.scope = scope;
        self
    }

    /// Set the human-readable display name (where the platform supports a separate name;
    /// the lookup identity is always the certificate fingerprint).
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Perform the install.
    pub fn run(self) -> Result<Report> {
        dispatch_install(self.cert, self.scope, self.label.as_deref())
    }
}

fn dispatch_install(cert: &Cert, scope: Scope, label: Option<&str>) -> Result<Report> {
    #[cfg(target_os = "linux")]
    {
        linux::install(cert, scope, label)
    }
    #[cfg(target_os = "macos")]
    {
        darwin::install(cert, scope, label)
    }
    #[cfg(windows)]
    {
        windows::install(cert, scope, label)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = (cert, scope, label);
        Err(TrustError::Unsupported)
    }
}

fn dispatch_uninstall(cert: &Cert, scope: Scope) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::uninstall(cert, scope)
    }
    #[cfg(target_os = "macos")]
    {
        darwin::uninstall(cert, scope)
    }
    #[cfg(windows)]
    {
        windows::uninstall(cert, scope)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = (cert, scope);
        Err(TrustError::Unsupported)
    }
}

fn dispatch_is_installed(cert: &Cert, scope: Scope) -> Result<bool> {
    #[cfg(target_os = "linux")]
    {
        linux::is_installed(cert, scope)
    }
    #[cfg(target_os = "macos")]
    {
        darwin::is_installed(cert, scope)
    }
    #[cfg(windows)]
    {
        windows::is_installed(cert, scope)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = (cert, scope);
        Err(TrustError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};

    fn gen_ca() -> Cert {
        let mut p = CertificateParams::new(vec![]).unwrap();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        p.distinguished_name
            .push(rcgen::DnType::CommonName, "os-truststore test root");
        let k = KeyPair::generate().unwrap();
        Cert::from_pem(p.self_signed(&k).unwrap().pem()).unwrap()
    }

    #[test]
    fn fresh_ca_is_not_installed_and_install_never_panics() {
        let ca = gen_ca();
        // A freshly generated CA must never report as already trusted. Some platforms may
        // need elevation even to open the store, so tolerate an error — but never a
        // false positive.
        if let Ok(present) = is_installed(&ca) {
            assert!(!present, "a fresh CA must not report as installed");
        }
        // Must return a Result, never panic. Non-elevated CI typically yields
        // NeedsElevation / InteractiveAuthRequired — all acceptable.
        let _ = install(&ca);
    }

    #[test]
    fn install_builder_defaults_to_system() {
        let ca = gen_ca();
        let b = Install::new(&ca);
        assert_eq!(b.scope, Scope::System);
        assert!(b.label.is_none());
    }

    // The real install → verify → remove round-trip (which mutates the OS store and needs
    // elevation) lives in tests/roundtrip.rs as an `#[ignore]`d, rcgen-free integration
    // test so the distro-container CI job can run it with only a Rust toolchain.
}
