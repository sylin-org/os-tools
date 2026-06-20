//! macOS — `security` CLI with honest degradation and scope-aware keychain selection.
//!
//! Root sufficed for headless admin-domain trust only through 10.15; Big Sur+ forces
//! interactive authorization, and 14.7.5+/15.x make unattended admin trust effectively
//! MDM-only. The CLI can also exit 0 yet leave the cert untrusted. So: attempt the add,
//! **verify by read-back**, and report honestly (`InstalledNotTrusted` /
//! `InteractiveAuthRequired`) rather than claiming silent system trust.
//!
//! [`Scope::System`] uses the admin domain (`-d`) on the System keychain (needs
//! elevation/authorization). [`Scope::CurrentUser`] uses the user's default keychain with
//! user-domain trust (no `-d`, no elevation).

use std::io::Write as _;
use std::process::Command;

use tempfile::NamedTempFile;

use crate::cert::Cert;
use crate::error::{Result, TrustError};
use crate::{Report, Scope};

const SYSTEM_KEYCHAIN: &str = "/Library/Keychains/System.keychain";

/// Write the PEM to a race-free temp file (random name, `O_EXCL`) for the `security` CLI.
/// The returned handle deletes the file when dropped.
fn temp_pem(cert: &Cert) -> Result<NamedTempFile> {
    let mut f = tempfile::Builder::new()
        .prefix("os-truststore-")
        .suffix(".pem")
        .tempfile()?;
    f.write_all(cert.pem().as_bytes())?;
    f.flush()?;
    Ok(f)
}

/// The keychain to query for `find-certificate`; `None` means the default keychain.
fn keychain(scope: Scope) -> Option<&'static str> {
    match scope {
        Scope::System => Some(SYSTEM_KEYCHAIN),
        Scope::CurrentUser => None,
    }
}

fn looks_like_auth_failure(stderr: &str) -> bool {
    let s = stderr.to_lowercase();
    s.contains("authorization")
        || s.contains("interaction")
        || s.contains("not allowed")
        || s.contains("denied")
        || s.contains("user canceled")
        || s.contains("user cancelled")
}

pub fn install(cert: &Cert, scope: Scope, label: Option<&str>) -> Result<Report> {
    // macOS shows the certificate subject in Keychain Access; there is no separate display
    // name we set here, so the label is accepted for API symmetry but not applied.
    let _ = label;

    if is_installed(cert, scope)? {
        return Ok(Report::AlreadyInstalled);
    }

    let pem = temp_pem(cert)?;
    let mut cmd = Command::new("security");
    cmd.arg("add-trusted-cert");
    if matches!(scope, Scope::System) {
        cmd.args(["-d", "-k", SYSTEM_KEYCHAIN]);
    }
    cmd.args(["-r", "trustRoot"]).arg(pem.path());
    let output = cmd.output();
    drop(pem); // remove the temp file regardless of result
    let output = output?;

    if output.status.success() {
        // Exit 0 does not guarantee trust on modern macOS — verify by read-back.
        if is_installed(cert, scope)? {
            tracing::info!("CA installed in macOS keychain");
            Ok(Report::Installed)
        } else {
            Ok(Report::InstalledNotTrusted {
                reason: "the certificate was added but could not be confirmed present on \
                         read-back (trust may require interactive authorization)"
                    .to_string(),
            })
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if looks_like_auth_failure(&stderr) {
            Err(TrustError::InteractiveAuthRequired)
        } else {
            Err(TrustError::CommandFailed {
                stderr: stderr.trim().to_string(),
            })
        }
    }
}

pub fn is_installed(cert: &Cert, scope: Scope) -> Result<bool> {
    let mut cmd = Command::new("security");
    cmd.args(["find-certificate", "-a", "-Z"]);
    if let Some(kc) = keychain(scope) {
        cmd.arg(kc);
    }
    let output = cmd.output()?;
    if !output.status.success() {
        return Ok(false);
    }
    let want = cert.fingerprint_hex().to_uppercase();
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("SHA-256 hash:") {
            if rest.trim().eq_ignore_ascii_case(&want) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub fn uninstall(cert: &Cert, scope: Scope) -> Result<()> {
    if !is_installed(cert, scope)? {
        return Ok(());
    }
    let pem = temp_pem(cert)?;
    let mut cmd = Command::new("security");
    cmd.arg("remove-trusted-cert");
    if matches!(scope, Scope::System) {
        cmd.arg("-d");
    }
    cmd.arg(pem.path());
    let output = cmd.output();
    drop(pem);
    let output = output?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if looks_like_auth_failure(&stderr) {
            Err(TrustError::InteractiveAuthRequired)
        } else {
            Err(TrustError::CommandFailed {
                stderr: stderr.trim().to_string(),
            })
        }
    }
}
