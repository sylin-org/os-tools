//! Typed, actionable errors. Every failure tells the caller what to do; we never panic.

use std::io;

/// Errors from trust-store operations. Non-exhaustive so new variants are not breaking.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TrustError {
    /// The supplied certificate is not a CA (no `CA:TRUE` basic constraint) — e.g. a leaf.
    #[error("not a CA certificate: {0}")]
    NotCaCertificate(String),

    /// The certificate could not be parsed as PEM/DER X.509.
    #[error("invalid certificate: {0}")]
    InvalidCertificate(String),

    /// No writable system trust anchor store was found (unknown/unsupported Linux distro).
    #[error("no writable system trust anchor store found on this system")]
    StoreNotFound,

    /// The distro's trust-store update tool is not installed (e.g. minimal/musl images).
    /// `hint` carries the exact remediation (e.g. `apk add ca-certificates`).
    #[error("the trust-store update tool is missing — {hint}")]
    StoreToolMissing { hint: String },

    /// Installing into the system store needs elevation, and the process is not elevated.
    /// `detail` carries the manual remedy (which dir/command to run as root/admin).
    #[error("installing into the system trust store requires elevated privileges — {detail}")]
    NeedsElevation { detail: String },

    /// The OS requires interactive authorization to set certificate trust
    /// (macOS 11+; effectively MDM-only headless on 14.7.5+/15.x). Not completable in CI.
    #[error(
        "the OS requires interactive authorization to set certificate trust; \
             a headless/daemon context cannot complete this (macOS: use an MDM \
             configuration profile for unattended trust)"
    )]
    InteractiveAuthRequired,

    /// An underlying OS tool / API call failed. `stderr` carries the captured output.
    #[error("trust store command failed: {stderr}")]
    CommandFailed { stderr: String },

    /// An I/O error (writing the anchor file, reading the store, …).
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// The current platform has no supported trust-store backend.
    #[error("the trust store is not supported on this platform")]
    Unsupported,
}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, TrustError>;
