//! CVE regression tests — MASWE-0069: WebView file access patterns.
//!
//! Milestone 9 — BDD: file:// and content:// URL patterns blocked in WebView.
#![cfg(feature = "mobile-platform")]
use secure_boundary::platform::{PlatformRejection, WebViewUrlValidator};

/// MASWE-0069: file:// URL must be blocked in WebView.
#[test]
fn maswe_0069_file_url_blocked() {
    let validator = WebViewUrlValidator::new().with_allowed_domains(&["example.com"]);
    let result = validator.validate("file:///etc/passwd");
    assert_eq!(
        result.unwrap_err(),
        PlatformRejection::FileAccessBlocked,
        "file:// URLs must be blocked in WebView context"
    );
}

/// MASWE-0069: file:// with path traversal must be blocked.
#[test]
fn maswe_0069_file_traversal_blocked() {
    let validator = WebViewUrlValidator::new().with_allowed_domains(&["example.com"]);
    let result = validator.validate("file:///data/data/../../../etc/passwd");
    // Should be rejected (either FileAccessBlocked or PathTraversal)
    assert!(
        result.is_err(),
        "file:// with path traversal must be rejected"
    );
}

/// MASWE-0069: content:// scheme should be treated as insecure in WebView.
#[test]
fn maswe_0069_content_scheme_blocked() {
    let validator = WebViewUrlValidator::new().with_allowed_domains(&["example.com"]);
    let result = validator.validate("content://com.example.provider/data");
    assert!(
        result.is_err(),
        "content:// URLs must be blocked in WebView context"
    );
}

/// MASWE-0069: HTTPS URL with allowed domain passes WebView validation.
#[test]
fn maswe_0069_https_allowed_domain() {
    let validator = WebViewUrlValidator::new().with_allowed_domains(&["example.com"]);
    let result = validator.validate("https://example.com/page");
    assert!(
        result.is_ok(),
        "HTTPS with allowed domain should pass: {result:?}"
    );
}

/// MASWE-0069: HTTPS URL with disallowed domain is rejected.
#[test]
fn maswe_0069_https_disallowed_domain() {
    let validator = WebViewUrlValidator::new().with_allowed_domains(&["example.com"]);
    let result = validator.validate("https://evil.com/steal");
    assert!(
        result.is_err(),
        "HTTPS with disallowed domain should be rejected"
    );
}

/// MASWE-0069: JavaScript scheme must be blocked in WebView.
#[test]
fn maswe_0069_javascript_in_webview() {
    let validator = WebViewUrlValidator::new().with_allowed_domains(&["example.com"]);
    let result = validator.validate("javascript:alert(1)");
    assert!(result.is_err(), "javascript: must be blocked in WebView");
}

/// MASWE-0069: data: scheme must be blocked in WebView.
#[test]
fn maswe_0069_data_scheme_blocked() {
    let validator = WebViewUrlValidator::new().with_allowed_domains(&["example.com"]);
    let result = validator.validate("data:text/html,<h1>evil</h1>");
    assert!(result.is_err(), "data: scheme must be blocked in WebView");
}
