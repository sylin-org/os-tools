//! [`Cert`] — a parsed, validated CA certificate. The unit of **identity** in this crate:
//! you install/query/remove with the same `Cert`, and the crate derives a stable identity
//! (SHA-256 of the DER) internally. No caller-supplied names to invent or track.

use std::fmt::Write as _;

use sha2::{Digest, Sha256};

use crate::error::{Result, TrustError};

/// A validated CA certificate.
///
/// Construct with [`Cert::from_pem`] / [`Cert::from_der`]; both reject anything that is not
/// a CA certificate (the gate that stops a leaf/server cert being installed as a root).
///
/// Two `Cert`s are equal iff their DER bytes are equal; the type is `Hash`/`Eq` so it can
/// be used as a map key or de-duplicated by identity.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Cert {
    der: Vec<u8>,
    pem: String,
    fingerprint: [u8; 32],
    common_name: Option<String>,
}

impl Cert {
    /// Parse a single `CERTIFICATE` PEM block and validate it is a CA certificate.
    pub fn from_pem(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let parsed = ::pem::parse(bytes.as_ref()).map_err(|e| {
            TrustError::InvalidCertificate(format!("not a valid PEM document: {e}"))
        })?;
        if parsed.tag() != "CERTIFICATE" {
            return Err(TrustError::InvalidCertificate(format!(
                "expected a CERTIFICATE PEM block, found {:?}",
                parsed.tag()
            )));
        }
        Self::from_der(parsed.contents())
    }

    /// Parse DER bytes and validate the certificate is a CA.
    pub fn from_der(bytes: impl AsRef<[u8]>) -> Result<Self> {
        use x509_parser::prelude::{FromDer, X509Certificate};

        let der = bytes.as_ref().to_vec();
        let (_, cert) = X509Certificate::from_der(&der).map_err(|e| {
            TrustError::InvalidCertificate(format!("not a valid X.509 certificate: {e}"))
        })?;

        // Gate: BasicConstraints CA flag must be present and true.
        let is_ca = matches!(cert.basic_constraints(), Ok(Some(bc)) if bc.value.ca);
        if !is_ca {
            return Err(TrustError::NotCaCertificate(
                "the certificate has no CA basic constraint \
                 (you passed a leaf/server cert, not a root)"
                    .into(),
            ));
        }

        let common_name = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(str::to_string);

        let fingerprint: [u8; 32] = Sha256::digest(&der).into();

        // Re-encode canonically so we install exactly the bytes we parsed.
        let pem = ::pem::encode(&::pem::Pem::new("CERTIFICATE", der.clone()));

        Ok(Cert {
            der,
            pem,
            fingerprint,
            common_name,
        })
    }

    /// The canonical single-cert PEM.
    pub fn pem(&self) -> &str {
        &self.pem
    }

    /// The DER bytes.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The certificate's Common Name, if present.
    pub fn common_name(&self) -> Option<&str> {
        self.common_name.as_deref()
    }

    /// SHA-256 fingerprint of the DER — the stable identity.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// SHA-256 fingerprint as lowercase hex.
    pub fn fingerprint_hex(&self) -> String {
        hex(&self.fingerprint)
    }

    /// Short fingerprint marker (first 64 bits) — the deterministic key embedded in the
    /// Linux anchor filename so `is_installed`/`uninstall` can find it from the cert alone.
    #[allow(dead_code)] // used by the Linux + macOS backends only
    pub(crate) fn short_fp(&self) -> String {
        hex(&self.fingerprint[..8])
    }

    /// Human-friendly display component: explicit label > cert CN > a generic default.
    /// Used as the readable prefix of the Linux filename and (where supported) the store
    /// display name. Never the lookup key — that is always the fingerprint.
    #[allow(dead_code)] // used by the Linux backend only
    pub(crate) fn display_label(&self, label: Option<&str>) -> String {
        if let Some(l) = label {
            let s = sanitize_label(l);
            if !s.is_empty() {
                return s;
            }
        }
        if let Some(cn) = &self.common_name {
            let s = sanitize_label(cn);
            if !s.is_empty() {
                return s;
            }
        }
        "os-truststore-root".to_string()
    }
}

impl std::fmt::Debug for Cert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cert")
            .field("common_name", &self.common_name)
            .field("fingerprint", &self.fingerprint_hex())
            .finish()
    }
}

/// Lowercase-hex encode bytes without a per-byte allocation.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Make a string safe as a filename component / display name: keep ASCII alphanumerics and
/// `_`, map everything else (including `.`, spaces, and path separators) to `-`, collapse
/// runs of `-`, and trim leading/trailing `-`. The result is never a path segment that can
/// escape a directory, and carries no extension dots.
#[allow(dead_code)] // used by display_label (Linux backend) + tests
fn sanitize_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_dash = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            out.push(c);
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};

    fn ca_pem(cn: &str) -> String {
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        let key = KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().pem()
    }

    fn leaf_pem() -> String {
        let params = CertificateParams::new(vec!["leaf.example.com".to_string()]).unwrap();
        let key = KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().pem()
    }

    #[test]
    fn accepts_ca_and_extracts_cn() {
        let c = Cert::from_pem(ca_pem("My Org Root")).unwrap();
        assert_eq!(c.common_name(), Some("My Org Root"));
        assert_eq!(c.fingerprint_hex().len(), 64);
        assert_eq!(c.short_fp().len(), 16);
        assert!(c.pem().contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn rejects_leaf() {
        let err = Cert::from_pem(leaf_pem()).unwrap_err();
        assert!(
            matches!(err, TrustError::NotCaCertificate(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(matches!(
            Cert::from_pem("not a pem").unwrap_err(),
            TrustError::InvalidCertificate(_)
        ));
    }

    #[test]
    fn fingerprint_is_stable_and_der_roundtrips() {
        let pem = ca_pem("Stable");
        let a = Cert::from_pem(&pem).unwrap();
        let b = Cert::from_der(a.der()).unwrap();
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn display_label_prefers_label_then_cn_then_default() {
        let c = Cert::from_pem(ca_pem("Acme Root CA")).unwrap();
        assert_eq!(c.display_label(Some("Custom Name")), "Custom-Name");
        assert_eq!(c.display_label(None), "Acme-Root-CA");
        // A label that sanitizes to empty falls through to the CN.
        assert_eq!(c.display_label(Some("///")), "Acme-Root-CA");
    }

    #[test]
    fn equal_certs_hash_equal() {
        use std::collections::HashSet;
        let pem = ca_pem("Hashable");
        let a = Cert::from_pem(&pem).unwrap();
        let b = Cert::from_pem(&pem).unwrap();
        assert_eq!(a, b);
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }

    #[test]
    fn sanitize_blocks_path_tricks() {
        assert_eq!(sanitize_label("../../etc/passwd"), "etc-passwd");
        assert_eq!(sanitize_label("a/b:c*d"), "a-b-c-d");
    }
}
