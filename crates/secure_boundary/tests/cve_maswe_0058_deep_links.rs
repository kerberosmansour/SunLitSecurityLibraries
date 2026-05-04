//! CVE regression tests — MASWE-0058: Insecure deep link patterns.
//!
//! Milestone 9 — BDD: Scheme hijacking, path traversal, and dangerous schemes blocked.
#![cfg(feature = "mobile-platform")]
use secure_boundary::platform::{DeepLinkValidator, PlatformRejection};

/// MASWE-0058: javascript: scheme must be blocked (XSS via deep link).
#[test]
fn maswe_0058_javascript_scheme_blocked() {
    let validator = DeepLinkValidator::new(&["myapp", "https"]);
    let result = validator.validate("javascript:alert(document.cookie)");
    assert_eq!(
        result.unwrap_err(),
        PlatformRejection::DangerousScheme,
        "javascript: scheme must be rejected as dangerous"
    );
}

/// MASWE-0058: data: scheme must be blocked.
#[test]
fn maswe_0058_data_scheme_blocked() {
    let validator = DeepLinkValidator::new(&["myapp", "https"]);
    let result = validator.validate("data:text/html,<script>alert(1)</script>");
    assert_eq!(result.unwrap_err(), PlatformRejection::DangerousScheme,);
}

/// MASWE-0058: vbscript: scheme must be blocked.
#[test]
fn maswe_0058_vbscript_scheme_blocked() {
    let validator = DeepLinkValidator::new(&["myapp", "https"]);
    let result = validator.validate("vbscript:MsgBox");
    assert_eq!(result.unwrap_err(), PlatformRejection::DangerousScheme,);
}

/// MASWE-0058: blob: scheme must be blocked.
#[test]
fn maswe_0058_blob_scheme_blocked() {
    let validator = DeepLinkValidator::new(&["myapp", "https"]);
    let result = validator.validate("blob:http://evil.com/data");
    assert_eq!(result.unwrap_err(), PlatformRejection::DangerousScheme,);
}

/// MASWE-0058: Path traversal in deep link must be blocked.
#[test]
fn maswe_0058_path_traversal_blocked() {
    let validator = DeepLinkValidator::new(&["myapp"]);
    let result = validator.validate("myapp://host/../../etc/passwd");
    assert_eq!(
        result.unwrap_err(),
        PlatformRejection::PathTraversal,
        "Path traversal must be detected and rejected"
    );
}

/// MASWE-0058: URL-encoded path traversal must be blocked.
#[test]
fn maswe_0058_encoded_path_traversal_blocked() {
    let validator = DeepLinkValidator::new(&["myapp"]);
    let result = validator.validate("myapp://host/..%2f..%2fetc%2fpasswd");
    assert_eq!(
        result.unwrap_err(),
        PlatformRejection::PathTraversal,
        "URL-encoded path traversal must be detected"
    );
}

/// MASWE-0058: Unregistered scheme must be rejected.
#[test]
fn maswe_0058_unregistered_scheme_rejected() {
    let validator = DeepLinkValidator::new(&["myapp"]);
    let result = validator.validate("evilapp://steal/data");
    assert_eq!(
        result.unwrap_err(),
        PlatformRejection::InvalidScheme,
        "Schemes not in the allow list must be rejected"
    );
}

/// MASWE-0058: Valid deep link with allowed scheme succeeds.
#[test]
fn maswe_0058_valid_deep_link_succeeds() {
    let validator = DeepLinkValidator::new(&["myapp", "https"]);
    let result = validator.validate("myapp://host/path/to/resource");
    assert!(result.is_ok(), "Valid deep link should succeed");
    assert_eq!(result.unwrap().as_inner(), "myapp://host/path/to/resource");
}

/// MASWE-0058: Case-insensitive dangerous scheme detection.
#[test]
fn maswe_0058_case_insensitive_javascript() {
    let validator = DeepLinkValidator::new(&["myapp"]);
    let result = validator.validate("JavaScript:alert(1)");
    assert_eq!(
        result.unwrap_err(),
        PlatformRejection::DangerousScheme,
        "Dangerous scheme detection must be case-insensitive"
    );
}
