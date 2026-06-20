//! Linux — the exhaust-all-methods orchestrator.
//!
//! There is no API: write a PEM to the distro's admin anchor dir, then run the distro's
//! refresh tool. Distro detection + anchor naming are pure logic in [`crate::detect`]
//! (unit-tested on every host); this module performs the filesystem writes and tool
//! invocations. We require the refresh tool to exist (else a loud `StoreToolMissing`) and
//! never silently no-op. Privileged write is direct-when-root; otherwise `NeedsElevation`
//! with the manual remedy (no `sudo` shell-out — it hard-fails in non-tty daemon contexts).

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cert::Cert;
use crate::detect::{self, AnchorSpec};
use crate::error::{Result, TrustError};
use crate::{Report, Scope};

/// Detect the distro's anchor spec: `/etc/os-release` ID/ID_LIKE first, then fall back to
/// directory existence (covers derivatives + missing os-release).
fn detect_spec() -> Option<AnchorSpec> {
    detect::spec_for_ids(&os_release_ids()).or_else(detect::spec_by_existing_dir)
}

fn os_release_ids() -> Vec<String> {
    std::fs::read_to_string("/etc/os-release")
        .map(|c| detect::parse_os_release(&c))
        .unwrap_or_default()
}

fn is_root() -> bool {
    // SAFETY: geteuid is always safe; it reads the process effective uid and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

fn marker(cert: &Cert, spec: &AnchorSpec) -> String {
    detect::marker_suffix(&cert.short_fp(), spec.ext)
}

fn anchor_path(cert: &Cert, spec: &AnchorSpec, label: Option<&str>) -> PathBuf {
    let name = detect::anchor_filename(&cert.display_label(label), &cert.short_fp(), spec.ext);
    Path::new(spec.dir).join(name)
}

fn run_refresh(spec: &AnchorSpec) -> Result<()> {
    let out = Command::new(spec.refresh[0])
        .args(&spec.refresh[1..])
        .output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(TrustError::CommandFailed {
            stderr: format!(
                "`{}` exit {}: {}",
                spec.refresh.join(" "),
                out.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        })
    }
}

fn tool_hint(tool: &str) -> String {
    match tool {
        "update-ca-certificates" => {
            "install the `ca-certificates` package (e.g. `apk add ca-certificates` or \
             `apt-get install -y ca-certificates`)"
                .to_string()
        }
        "update-ca-trust" => {
            "install the `ca-certificates` package (e.g. `dnf install -y ca-certificates`)"
                .to_string()
        }
        "trust" => "install `p11-kit` (e.g. `pacman -S p11-kit`)".to_string(),
        other => format!("install the package providing `{other}`"),
    }
}

pub fn install(cert: &Cert, scope: Scope, label: Option<&str>) -> Result<Report> {
    // Linux has no per-user system store; both scopes use the system anchor dirs.
    let _ = scope;

    let spec = detect_spec().ok_or(TrustError::StoreNotFound)?;
    let tool = spec.refresh[0];
    if which::which(tool).is_err() {
        return Err(TrustError::StoreToolMissing {
            hint: tool_hint(tool),
        });
    }
    if is_installed(cert, scope)? {
        return Ok(Report::AlreadyInstalled);
    }

    let path = anchor_path(cert, &spec, label);
    if !is_root() {
        return Err(TrustError::NeedsElevation {
            detail: format!(
                "run as root, or place the CA PEM at {} and run `{}`",
                path.display(),
                spec.refresh.join(" ")
            ),
        });
    }

    std::fs::create_dir_all(spec.dir)?;
    std::fs::write(&path, cert.pem())?;
    run_refresh(&spec)?;

    if !is_installed(cert, scope)? {
        return Err(TrustError::CommandFailed {
            stderr: format!(
                "wrote {} but the cert is not present after `{}` — \
                 check the file extension ({}) and that the tool succeeded",
                path.display(),
                spec.refresh.join(" "),
                spec.ext
            ),
        });
    }
    tracing::info!(path = %path.display(), "CA installed in system trust store");
    Ok(Report::Installed)
}

pub fn is_installed(cert: &Cert, scope: Scope) -> Result<bool> {
    let _ = scope;
    let Some(spec) = detect_spec() else {
        return Ok(false);
    };
    let marker = marker(cert, &spec);
    match std::fs::read_dir(spec.dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.ends_with(&marker) {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

pub fn uninstall(cert: &Cert, scope: Scope) -> Result<()> {
    let _ = scope;
    let Some(spec) = detect_spec() else {
        return Ok(());
    };
    let marker = marker(cert, &spec);

    let mut to_remove = Vec::new();
    if let Ok(entries) = std::fs::read_dir(spec.dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name.ends_with(&marker) {
                    to_remove.push(entry.path());
                }
            }
        }
    }
    if to_remove.is_empty() {
        return Ok(()); // idempotent: nothing to do
    }
    if !is_root() {
        return Err(TrustError::NeedsElevation {
            detail: format!("run as root to remove {}", to_remove[0].display()),
        });
    }
    for path in to_remove {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    if which::which(spec.refresh[0]).is_ok() {
        run_refresh(&spec)?;
    }
    Ok(())
}
