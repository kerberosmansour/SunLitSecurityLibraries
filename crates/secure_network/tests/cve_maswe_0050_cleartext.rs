//! CVE regression tests — MASWE-0050: Cleartext traffic variants.
//!
//! Milestone 9 — BDD: Cleartext traffic (HTTP, custom ports, FTP) always detected.
use secure_network::{CleartextDetector, CleartextResult};

/// MASWE-0050: Plain HTTP traffic must always be blocked.
#[test]
fn maswe_0050_http_always_blocked() {
    let detector = CleartextDetector::new();
    assert_eq!(
        detector.check("http://api.example.com/v1/data"),
        CleartextResult::CleartextBlocked,
        "Plain HTTP to external host must be blocked"
    );
}

/// MASWE-0050: HTTP on a non-standard port must still be blocked.
#[test]
fn maswe_0050_http_custom_port_blocked() {
    let detector = CleartextDetector::new();
    assert_eq!(
        detector.check("http://api.example.com:8080/v1/data"),
        CleartextResult::CleartextBlocked,
        "HTTP on custom port 8080 must be blocked"
    );
}

/// MASWE-0050: FTP (cleartext file transfer) must be detected as insecure.
#[test]
fn maswe_0050_ftp_detected() {
    let detector = CleartextDetector::new();
    match detector.check("ftp://files.example.com/uploads") {
        CleartextResult::InsecureScheme { scheme } => {
            assert_eq!(scheme, "ftp", "FTP must be identified by scheme name");
        }
        other => panic!("FTP must be InsecureScheme, got: {other:?}"),
    }
}

/// MASWE-0050: Telnet must be detected as insecure.
#[test]
fn maswe_0050_telnet_detected() {
    let detector = CleartextDetector::new();
    match detector.check("telnet://router.local") {
        CleartextResult::InsecureScheme { scheme } => {
            assert_eq!(scheme, "telnet");
        }
        other => panic!("Telnet must be InsecureScheme, got: {other:?}"),
    }
}

/// MASWE-0050: HTTPS must be recognized as secure.
#[test]
fn maswe_0050_https_secure() {
    let detector = CleartextDetector::new();
    assert_eq!(
        detector.check("https://api.example.com/v1/data"),
        CleartextResult::Secure,
    );
}

/// MASWE-0050: WebSocket (ws://) must be treated as cleartext.
#[test]
fn maswe_0050_ws_cleartext() {
    let detector = CleartextDetector::new();
    assert_eq!(
        detector.check("ws://realtime.example.com/stream"),
        CleartextResult::CleartextBlocked,
    );
}

/// MASWE-0050: Secure WebSocket (wss://) must be treated as secure.
#[test]
fn maswe_0050_wss_secure() {
    let detector = CleartextDetector::new();
    assert_eq!(
        detector.check("wss://realtime.example.com/stream"),
        CleartextResult::Secure,
    );
}

/// MASWE-0050: Localhost exemption when enabled allows http://localhost.
#[test]
fn maswe_0050_localhost_exemption() {
    let detector = CleartextDetector::new().with_localhost_exemption(true);
    assert_eq!(
        detector.check("http://localhost:8080/api"),
        CleartextResult::ExemptedLocalhost,
    );
    assert_eq!(
        detector.check("http://127.0.0.1/api"),
        CleartextResult::ExemptedLocalhost,
    );
}

/// MASWE-0050: Localhost exemption disabled still blocks http://localhost.
#[test]
fn maswe_0050_no_localhost_exemption() {
    let detector = CleartextDetector::new();
    assert_eq!(
        detector.check("http://localhost:8080/api"),
        CleartextResult::CleartextBlocked,
    );
}
