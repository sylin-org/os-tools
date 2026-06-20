//! Pure, platform-agnostic Linux trust-anchor detection + naming.
//!
//! Kept free of filesystem and platform `cfg` so the core logic (distro → anchor spec,
//! os-release parsing, anchor filenames) is unit-tested on *every* CI host, not only Linux.
//! The actual filesystem writes / `Command` calls live in `linux.rs`.

#![allow(dead_code)] // consumed by the Linux backend (cfg-gated) and by these tests

use std::path::Path;

/// One distro family's trust-anchor convention.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AnchorSpec {
    /// Admin anchor directory (high-priority, writable).
    pub dir: &'static str,
    /// Required file extension (load-bearing on Debian/Arch).
    pub ext: &'static str,
    /// The refresh command + args; `refresh[0]` is the binary to probe.
    pub refresh: &'static [&'static str],
}

pub(crate) const RHEL: AnchorSpec = AnchorSpec {
    dir: "/etc/pki/ca-trust/source/anchors",
    ext: "pem",
    refresh: &["update-ca-trust", "extract"],
};
pub(crate) const DEBIAN: AnchorSpec = AnchorSpec {
    dir: "/usr/local/share/ca-certificates",
    ext: "crt",
    refresh: &["update-ca-certificates"],
};
pub(crate) const ARCH: AnchorSpec = AnchorSpec {
    dir: "/etc/ca-certificates/trust-source/anchors",
    ext: "crt",
    refresh: &["trust", "extract-compat"],
};
// openSUSE/SLE admin dir corrected to /etc/pki/trust/anchors (see docs/PRIOR-ART.md — the
// references' /usr/share/... is the lower-priority vendor dir). Tier-3 until verified.
pub(crate) const SUSE: AnchorSpec = AnchorSpec {
    dir: "/etc/pki/trust/anchors",
    ext: "pem",
    refresh: &["update-ca-certificates"],
};

/// Directory-existence fallback order (also the priority when os-release is ambiguous).
const FALLBACK_ORDER: [AnchorSpec; 4] = [RHEL, DEBIAN, ARCH, SUSE];

/// Parse `/etc/os-release` content into lowercased `ID` + `ID_LIKE` tokens.
pub(crate) fn parse_os_release(content: &str) -> Vec<String> {
    let mut ids = Vec::new();
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("ID=") {
            ids.push(unquote(v));
        } else if let Some(v) = line.strip_prefix("ID_LIKE=") {
            ids.extend(unquote(v).split_whitespace().map(str::to_string));
        }
    }
    ids.iter().map(|s| s.to_lowercase()).collect()
}

fn unquote(s: &str) -> String {
    s.trim().trim_matches(['"', '\'']).to_string()
}

/// Map os-release IDs (ID + ID_LIKE) to an anchor spec.
pub(crate) fn spec_for_ids(ids: &[String]) -> Option<AnchorSpec> {
    let has = |needles: &[&str]| ids.iter().any(|id| needles.contains(&id.as_str()));

    if has(&[
        "fedora",
        "rhel",
        "centos",
        "rocky",
        "almalinux",
        "ol",
        "amzn",
    ]) {
        return Some(RHEL);
    }
    if has(&[
        "debian",
        "ubuntu",
        "alpine",
        "linuxmint",
        "pop",
        "raspbian",
        "kali",
        "devuan",
        "elementary",
    ]) {
        return Some(DEBIAN);
    }
    if has(&["arch", "manjaro", "artix", "endeavouros", "garuda"]) {
        return Some(ARCH);
    }
    if has(&[
        "opensuse",
        "opensuse-leap",
        "opensuse-tumbleweed",
        "sles",
        "sled",
        "suse",
    ]) {
        return Some(SUSE);
    }
    None
}

/// Filesystem fallback: the first known anchor directory that exists.
pub(crate) fn spec_by_existing_dir() -> Option<AnchorSpec> {
    FALLBACK_ORDER
        .into_iter()
        .find(|spec| Path::new(spec.dir).is_dir())
}

/// The anchor filename: a readable prefix + the deterministic fingerprint marker.
pub(crate) fn anchor_filename(prefix: &str, short_fp: &str, ext: &str) -> String {
    format!("{prefix}-{short_fp}.{ext}")
}

/// The deterministic suffix that identifies our file regardless of the readable prefix.
pub(crate) fn marker_suffix(short_fp: &str, ext: &str) -> String {
    format!("-{short_fp}.{ext}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_distros() {
        assert_eq!(spec_for_ids(&["debian".into()]), Some(DEBIAN));
        assert_eq!(spec_for_ids(&["ubuntu".into()]), Some(DEBIAN));
        assert_eq!(spec_for_ids(&["alpine".into()]), Some(DEBIAN));
        assert_eq!(spec_for_ids(&["fedora".into()]), Some(RHEL));
        assert_eq!(spec_for_ids(&["rhel".into()]), Some(RHEL));
        assert_eq!(spec_for_ids(&["arch".into()]), Some(ARCH));
        assert_eq!(spec_for_ids(&["opensuse-tumbleweed".into()]), Some(SUSE));
        assert_eq!(spec_for_ids(&["sles".into()]), Some(SUSE));
        assert_eq!(spec_for_ids(&["plan9".into()]), None);
    }

    #[test]
    fn id_like_provides_fallback_for_derivatives() {
        let ids = parse_os_release("ID=frobos\nID_LIKE=\"debian\"\n");
        assert_eq!(spec_for_ids(&ids), Some(DEBIAN));
    }

    #[test]
    fn parses_quotes_and_lowercases() {
        let ids = parse_os_release("NAME=\"Ubuntu\"\nID=\"Ubuntu\"\nID_LIKE='debian'\n");
        assert!(ids.contains(&"ubuntu".to_string()));
        assert!(ids.contains(&"debian".to_string()));
    }

    #[test]
    fn spec_details_match_distro_conventions() {
        assert_eq!(RHEL.refresh, &["update-ca-trust", "extract"]);
        assert_eq!(ARCH.refresh, &["trust", "extract-compat"]);
        assert_eq!(DEBIAN.ext, "crt");
        assert_eq!(RHEL.ext, "pem");
        assert_eq!(SUSE.dir, "/etc/pki/trust/anchors");
    }

    #[test]
    fn filename_ends_with_marker() {
        // The idempotency invariant: the file install writes ends with the suffix
        // is_installed/uninstall scan for.
        let fp = "0123456789abcdef";
        let name = anchor_filename("My-Root", fp, "crt");
        let marker = marker_suffix(fp, "crt");
        assert!(name.ends_with(&marker), "{name} should end with {marker}");
        assert_eq!(name, "My-Root-0123456789abcdef.crt");
    }
}
