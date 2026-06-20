//! Real install -> verify -> remove round-trip against the actual OS trust store.
//!
//! `#[ignore]`d by default: it mutates the system store and needs elevation
//! (Administrator / root). Run explicitly:
//! `cargo test -p os-truststore --test roundtrip -- --ignored`.
//! The distro-container CI job runs this as root on each Linux family.
//!
//! Uses a long-lived **static** CA fixture (not `rcgen`), so this test target is pure
//! Rust — the CI containers need only a Rust toolchain plus the distro trust tooling, no
//! C compiler.

use os_truststore::{Cert, Report};

/// A self-signed P-256 CA certificate (`CA:TRUE`, `keyCertSign`), valid ~100 years.
/// Test fixture only: the matching private key was discarded at generation, so this is a
/// harmless throwaway trust anchor.
const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBqDCCAU2gAwIBAgIUNfpmvQqnA0S9VFcjSTPNrzdXKEkwCgYIKoZIzj0EAwIw
IDEeMBwGA1UEAwwVb3MtdHJ1c3RzdG9yZSBDSSBSb290MCAXDTI2MDYyMDAzMTEz
NloYDzIxMjYwNTI3MDMxMTM2WjAgMR4wHAYDVQQDDBVvcy10cnVzdHN0b3JlIENJ
IFJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQdX0tTY5nxrx7mLhgQ43kB
sThE4JVmriBgVfoVykc8eZEi5bnZ0oKGsAAxgq8JZixslOVZPA3Tu+94p/deJd+O
o2MwYTAdBgNVHQ4EFgQUfHR5BrLV+yAwF5BtCTJj8N+a8EgwHwYDVR0jBBgwFoAU
fHR5BrLV+yAwF5BtCTJj8N+a8EgwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8E
BAMCAQYwCgYIKoZIzj0EAwIDSQAwRgIhALSuKudffKZG3Cw1v53G0BIvhhlYLgVP
gtjA3hYuqzUcAiEAzDgIrER3h87w1BjNB3jpY552CGBkhzlCP9uINsNz4i0=
-----END CERTIFICATE-----
";

#[test]
fn fixture_parses_as_a_ca() {
    let ca = Cert::from_pem(TEST_CA_PEM).expect("the fixture must be a valid CA certificate");
    assert_eq!(ca.common_name(), Some("os-truststore CI Root"));
    assert_eq!(ca.fingerprint_hex().len(), 64);
}

#[test]
#[ignore = "mutates the OS trust store; needs admin/root"]
fn install_verify_remove_round_trip() {
    let ca = Cert::from_pem(TEST_CA_PEM).expect("fixture must parse");

    let report = os_truststore::install(&ca).expect("install should succeed with privileges");
    assert!(
        matches!(
            report,
            Report::Installed | Report::AlreadyInstalled | Report::InstalledNotTrusted { .. }
        ),
        "unexpected install report: {report:?}"
    );
    assert!(
        os_truststore::is_installed(&ca).expect("query"),
        "must be present after install"
    );

    // Re-install is idempotent.
    assert!(matches!(
        os_truststore::install(&ca).expect("reinstall"),
        Report::AlreadyInstalled | Report::Installed | Report::InstalledNotTrusted { .. }
    ));

    os_truststore::uninstall(&ca).expect("remove");
    assert!(
        !os_truststore::is_installed(&ca).expect("query"),
        "must be gone after remove"
    );

    // Uninstall of the now-absent cert is a no-op.
    os_truststore::uninstall(&ca).expect("second uninstall is idempotent");
}
