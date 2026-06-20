//! In-process trust — trust a CA **without touching the OS store**.
//!
//! This needs no elevation and works identically on every platform: build a
//! [`rustls::RootCertStore`] that trusts the CA, and use it for the clients you control.
//! For many callers this *is* "just works" — the OS-store install ([`crate::install`]) is
//! only needed when you also want *other* tools or browsers to trust the CA.
//!
//! Available with the `rustls` feature.
//!
//! ```no_run
//! # let ca = os_truststore::Cert::from_pem(b"").unwrap();
//! let roots = os_truststore::inprocess::rustls_root_store(&ca)?;
//! // let config = rustls::ClientConfig::builder()
//! //     .with_root_certificates(roots)
//! //     .with_no_client_auth();
//! # Ok::<(), os_truststore::TrustError>(())
//! ```
//!
//! For `reqwest`, you don't even need this module — use its own API directly:
//! `reqwest::Certificate::from_der(ca.der())` then `ClientBuilder::add_root_certificate`.

use crate::cert::Cert;
use crate::error::{Result, TrustError};

/// Build a [`rustls::RootCertStore`] that trusts `cert`.
///
/// The caller supplies the crypto provider when building the `ClientConfig`, so this
/// function does not depend on any particular provider.
pub fn rustls_root_store(cert: &Cert) -> Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    let der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    roots
        .add(der)
        .map_err(|e| TrustError::InvalidCertificate(e.to_string()))?;
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};

    #[test]
    fn builds_a_root_store_with_one_anchor() {
        let mut p = CertificateParams::new(vec![]).unwrap();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let k = KeyPair::generate().unwrap();
        let ca = Cert::from_pem(p.self_signed(&k).unwrap().pem()).unwrap();

        let roots = rustls_root_store(&ca).unwrap();
        assert_eq!(roots.len(), 1);
    }
}
