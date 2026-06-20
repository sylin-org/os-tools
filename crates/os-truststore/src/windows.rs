//! Windows — native CryptoAPI via the `schannel` crate (no `certutil` subprocess).
//!
//! We open the explicit store scope (LocalMachine / CurrentUser) — never the legacy
//! `CertOpenSystemStoreW`, which silently scopes to the current user. Install is
//! idempotent (`CertAdd::ReplaceExisting`); identity is the cert DER (SHA-256 thumbprint
//! equivalent). LocalMachine needs an already-elevated process.

use schannel::cert_context::CertContext;
use schannel::cert_store::{CertAdd, CertStore};

use crate::cert::Cert;
use crate::error::{Result, TrustError};
use crate::{Report, Scope};

const ERROR_ACCESS_DENIED: i32 = 5;

fn open(scope: Scope) -> Result<CertStore> {
    let result = match scope {
        Scope::System => CertStore::open_local_machine("Root"),
        Scope::CurrentUser => CertStore::open_current_user("Root"),
    };
    result.map_err(|e| classify(e, scope))
}

fn classify(e: std::io::Error, scope: Scope) -> TrustError {
    let denied = e.raw_os_error() == Some(ERROR_ACCESS_DENIED)
        || e.kind() == std::io::ErrorKind::PermissionDenied;
    if denied && scope == Scope::System {
        TrustError::NeedsElevation {
            detail: "run elevated (Administrator) to modify LocalMachine\\Root, or use \
                     Scope::CurrentUser for a per-user install"
                .to_string(),
        }
    } else {
        TrustError::CommandFailed {
            stderr: e.to_string(),
        }
    }
}

pub fn install(cert: &Cert, scope: Scope, label: Option<&str>) -> Result<Report> {
    // Windows shows the certificate's own subject in certmgr; a custom friendly name is a
    // future enhancement, so the label does not affect identity or lookup here.
    let _ = label;

    if is_installed(cert, scope)? {
        return Ok(Report::AlreadyInstalled);
    }
    let mut store = open(scope)?;
    let ctx = CertContext::new(cert.der()).map_err(|e| TrustError::CommandFailed {
        stderr: format!("failed to decode certificate: {e}"),
    })?;
    store
        .add_cert(&ctx, CertAdd::ReplaceExisting)
        .map_err(|e| classify(e, scope))?;
    tracing::info!("CA installed in Windows certificate store");
    Ok(Report::Installed)
}

pub fn is_installed(cert: &Cert, scope: Scope) -> Result<bool> {
    let store = open(scope)?;
    for ctx in store.certs() {
        if ctx.to_der() == cert.der() {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn uninstall(cert: &Cert, scope: Scope) -> Result<()> {
    let store = open(scope)?;
    for ctx in store.certs() {
        if ctx.to_der() == cert.der() {
            ctx.delete().map_err(|e| classify(e, scope))?;
        }
    }
    Ok(())
}
