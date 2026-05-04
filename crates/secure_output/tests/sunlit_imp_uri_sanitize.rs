//! BDD scenarios: sanitize_uri_scheme (M12)

use secure_output::sanitize_uri_scheme;

// Scenario: HTTPS allowed
#[test]
fn uri_https_allowed() {
    assert!(sanitize_uri_scheme("https://example.com").is_ok());
}

// Scenario: HTTP allowed
#[test]
fn uri_http_allowed() {
    assert!(sanitize_uri_scheme("http://example.com").is_ok());
}

// Scenario: mailto allowed
#[test]
fn uri_mailto_allowed() {
    assert!(sanitize_uri_scheme("mailto:user@example.com").is_ok());
}

// Scenario: javascript: blocked
#[test]
fn uri_javascript_blocked() {
    assert!(sanitize_uri_scheme("javascript:alert(1)").is_err());
}

// Scenario: data: blocked
#[test]
fn uri_data_blocked() {
    assert!(sanitize_uri_scheme("data:text/html,<script>alert(1)</script>").is_err());
}

// Scenario: vbscript: blocked
#[test]
fn uri_vbscript_blocked() {
    assert!(sanitize_uri_scheme("vbscript:msgbox(1)").is_err());
}

// Scenario: Case-insensitive blocking
#[test]
fn uri_case_insensitive_blocked() {
    assert!(sanitize_uri_scheme("JAVASCRIPT:alert(1)").is_err());
    assert!(sanitize_uri_scheme("JavaScript:alert(1)").is_err());
    assert!(sanitize_uri_scheme("DATA:text/html,x").is_err());
}

// Scenario: Relative URL allowed
#[test]
fn uri_relative_url_allowed() {
    assert!(sanitize_uri_scheme("/path/to/resource").is_ok());
}

// Scenario: Relative URL with query allowed
#[test]
fn uri_relative_url_with_query_allowed() {
    assert!(sanitize_uri_scheme("/search?q=hello").is_ok());
}

// Scenario: Empty string allowed (no scheme)
#[test]
fn uri_empty_string_allowed() {
    assert!(sanitize_uri_scheme("").is_ok());
}
