//! BDD acceptance tests for cleartext traffic detection (Milestone 1).

use secure_network::cleartext::*;
use security_events::kind::EventKind;
use security_events::sink::InMemorySink;

// --- Feature: Cleartext Traffic Detection ---

/// Scenario: HTTPS URL allowed
/// Given `CleartextDetector` enabled
/// When URL scheme is `https`
/// Then `CleartextResult::Secure`
#[test]
fn https_url_allowed() {
    let detector = CleartextDetector::new();
    assert_eq!(
        detector.check("https://api.example.com/data"),
        CleartextResult::Secure
    );
}

/// Scenario: HTTP URL blocked
/// Given `CleartextDetector` enabled
/// When URL scheme is `http`
/// Then `CleartextResult::CleartextBlocked` + security event
#[test]
fn http_url_blocked() {
    let detector = CleartextDetector::new();
    let sink = InMemorySink::new();
    let result = detector.check_and_emit("http://api.example.com/data", &sink);

    assert_eq!(result, CleartextResult::CleartextBlocked);
    let events = sink.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, EventKind::CleartextBlocked);
    assert_eq!(events[0].reason_code, Some("cleartext_http"));
}

/// Scenario: localhost HTTP exempted
/// Given `CleartextDetector` with localhost exemption
/// When `http://127.0.0.1`
/// Then `CleartextResult::ExemptedLocalhost`
#[test]
fn localhost_127_exempted() {
    let detector = CleartextDetector::new().with_localhost_exemption(true);
    assert_eq!(
        detector.check("http://127.0.0.1/api"),
        CleartextResult::ExemptedLocalhost
    );
}

#[test]
fn localhost_name_exempted() {
    let detector = CleartextDetector::new().with_localhost_exemption(true);
    assert_eq!(
        detector.check("http://localhost:3000/api"),
        CleartextResult::ExemptedLocalhost
    );
}

#[test]
fn localhost_ipv6_exempted() {
    let detector = CleartextDetector::new().with_localhost_exemption(true);
    assert_eq!(
        detector.check("http://[::1]:8080/api"),
        CleartextResult::ExemptedLocalhost
    );
}

#[test]
fn localhost_not_exempted_when_disabled() {
    let detector = CleartextDetector::new(); // exemption off by default
    assert_eq!(
        detector.check("http://127.0.0.1/api"),
        CleartextResult::CleartextBlocked
    );
}

/// Scenario: Custom port cleartext detected
/// Given `CleartextDetector` enabled
/// When `http://api.example.com:8080`
/// Then `CleartextResult::CleartextBlocked`
#[test]
fn custom_port_cleartext_detected() {
    let detector = CleartextDetector::new();
    assert_eq!(
        detector.check("http://api.example.com:8080/data"),
        CleartextResult::CleartextBlocked
    );
}

/// Scenario: FTP scheme blocked
/// Given `CleartextDetector` enabled
/// When URL scheme is `ftp`
/// Then `CleartextResult::InsecureScheme`
#[test]
fn ftp_scheme_blocked() {
    let detector = CleartextDetector::new();
    let sink = InMemorySink::new();
    let result = detector.check_and_emit("ftp://files.example.com/data", &sink);

    assert!(matches!(result, CleartextResult::InsecureScheme { .. }));
    if let CleartextResult::InsecureScheme { scheme } = &result {
        assert_eq!(scheme, "ftp");
    }
    let events = sink.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, EventKind::CleartextBlocked);
    assert_eq!(events[0].reason_code, Some("insecure_scheme"));
}

/// Scenario: WSS (WebSocket Secure) allowed
#[test]
fn wss_allowed() {
    let detector = CleartextDetector::new();
    assert_eq!(
        detector.check("wss://ws.example.com/stream"),
        CleartextResult::Secure
    );
}

/// Scenario: WS (WebSocket) blocked
#[test]
fn ws_blocked() {
    let detector = CleartextDetector::new();
    assert_eq!(
        detector.check("ws://ws.example.com/stream"),
        CleartextResult::CleartextBlocked
    );
}

/// Scenario: No event on secure URL
#[test]
fn no_event_on_secure_url() {
    let detector = CleartextDetector::new();
    let sink = InMemorySink::new();
    let result = detector.check_and_emit("https://secure.example.com", &sink);

    assert_eq!(result, CleartextResult::Secure);
    assert!(sink.events().is_empty());
}

/// Scenario: No event on exempted localhost
#[test]
fn no_event_on_exempted_localhost() {
    let detector = CleartextDetector::new().with_localhost_exemption(true);
    let sink = InMemorySink::new();
    let result = detector.check_and_emit("http://localhost:3000", &sink);

    assert_eq!(result, CleartextResult::ExemptedLocalhost);
    assert!(sink.events().is_empty());
}

/// Scenario: Case insensitive scheme detection
#[test]
fn case_insensitive_scheme() {
    let detector = CleartextDetector::new();
    assert_eq!(
        detector.check("HTTPS://SECURE.EXAMPLE.COM"),
        CleartextResult::Secure
    );
    assert_eq!(
        detector.check("HTTP://INSECURE.EXAMPLE.COM"),
        CleartextResult::CleartextBlocked
    );
}

/// Scenario: Malformed URL (no scheme) blocked
#[test]
fn no_scheme_blocked() {
    let detector = CleartextDetector::new();
    assert_eq!(
        detector.check("api.example.com/data"),
        CleartextResult::CleartextBlocked
    );
}

/// Scenario: Telnet scheme blocked
#[test]
fn telnet_scheme_blocked() {
    let detector = CleartextDetector::new();
    let result = detector.check("telnet://server.example.com");
    assert!(matches!(result, CleartextResult::InsecureScheme { .. }));
}
