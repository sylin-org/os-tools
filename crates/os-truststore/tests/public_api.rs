//! Public-API integration tests — the crate surface as an external user sees it.
//!
//! These do not require elevation: they assert the validation gate, idempotency contract,
//! and that unprivileged operations return *typed* errors (never a panic or a false
//! success). The real store-mutating round-trip is the `#[ignore]`d unit test
//! `install_verify_remove_round_trip` (run with `-- --ignored` on a privileged host /
//! the distro CI containers).

use os_truststore::{Cert, Install, Report, Scope, TrustError};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};

fn ca(cn: &str) -> Cert {
    let mut p = CertificateParams::new(vec![]).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    p.distinguished_name.push(rcgen::DnType::CommonName, cn);
    let k = KeyPair::generate().unwrap();
    Cert::from_pem(p.self_signed(&k).unwrap().pem()).unwrap()
}

fn leaf_pem() -> String {
    let p = CertificateParams::new(vec!["leaf.example.com".to_string()]).unwrap();
    let k = KeyPair::generate().unwrap();
    p.self_signed(&k).unwrap().pem()
}

#[test]
fn from_pem_rejects_a_leaf() {
    assert!(matches!(
        Cert::from_pem(leaf_pem()),
        Err(TrustError::NotCaCertificate(_))
    ));
}

#[test]
fn from_pem_rejects_garbage() {
    assert!(matches!(
        Cert::from_pem("definitely not a pem"),
        Err(TrustError::InvalidCertificate(_))
    ));
}

#[test]
fn from_der_roundtrips_and_keeps_identity() {
    let c = ca("Roundtrip Root");
    let again = Cert::from_der(c.der()).unwrap();
    assert_eq!(c, again);
    assert_eq!(c.fingerprint(), again.fingerprint());
    assert_eq!(c.common_name(), Some("Roundtrip Root"));
    assert_eq!(c.fingerprint_hex().len(), 64);
}

#[test]
fn fresh_ca_is_never_reported_installed() {
    let c = ca("Fresh Root");
    // Some platforms may need elevation even to read the store; tolerate an error, but a
    // freshly generated CA must never report as already installed.
    if let Ok(present) = os_truststore::is_installed(&c) {
        assert!(!present, "a fresh CA must not be installed");
    }
}

#[test]
fn install_without_privilege_is_typed_never_a_panic_or_false_success() {
    let c = ca("Unprivileged Root");
    match os_truststore::install(&c) {
        // A genuinely privileged runner may install for real — accept and clean up.
        Ok(Report::Installed | Report::AlreadyInstalled | Report::InstalledNotTrusted { .. }) => {
            let _ = os_truststore::uninstall(&c);
        }
        // The expected unprivileged outcomes — all typed, none a panic.
        Err(
            TrustError::NeedsElevation { .. }
            | TrustError::InteractiveAuthRequired
            | TrustError::CommandFailed { .. }
            | TrustError::StoreNotFound
            | TrustError::StoreToolMissing { .. },
        ) => {}
        other => panic!("unexpected install outcome: {other:?}"),
    }
}

#[test]
fn uninstall_of_absent_cert_is_idempotent() {
    let c = ca("Absent Root");
    match os_truststore::uninstall(&c) {
        Ok(()) => {}
        // Acceptable when the platform needs elevation even to open the store.
        Err(
            TrustError::NeedsElevation { .. }
            | TrustError::InteractiveAuthRequired
            | TrustError::CommandFailed { .. }
            | TrustError::StoreNotFound,
        ) => {}
        other => panic!("unexpected uninstall outcome: {other:?}"),
    }
}

#[test]
fn install_builder_constructs() {
    // Exercise the builder's fluent surface WITHOUT a real install: `run()` can block on a
    // headless macOS trust prompt. The run path is covered by `install()` above and the
    // crate's `no_run` doctest.
    let c = ca("Builder Root");
    let _builder = Install::new(&c)
        .scope(Scope::CurrentUser)
        .label("Builder Root");
}

#[cfg(feature = "rustls")]
#[test]
fn inprocess_root_store_builds_without_privilege() {
    let c = ca("InProcess Root");
    let roots = os_truststore::inprocess::rustls_root_store(&c).unwrap();
    assert_eq!(roots.len(), 1);
}
