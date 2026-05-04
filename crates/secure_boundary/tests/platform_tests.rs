//! BDD acceptance tests for `secure_boundary::platform` (Milestone 4 — MASVS-PLATFORM).
//!
//! Tests are feature-gated behind `mobile-platform`.

#![cfg(feature = "mobile-platform")]

use secure_boundary::platform::{
    ClipboardPolicy, DeepLinkValidator, PlatformRejection, ScreenshotPolicy, WebViewUrlValidator,
};
use security_core::classification::DataClassification;

// ── Feature: Deep Link Validation ────────────────────────────────────────────

#[test]
fn given_allowed_schemes_when_valid_scheme_url_then_accepted() {
    let validator = DeepLinkValidator::new(&["myapp", "myapp-debug"]);
    let result = validator.validate("myapp://profile/123");
    assert!(result.is_ok());
    assert_eq!(result.unwrap().as_inner(), "myapp://profile/123");
}

#[test]
fn given_allowed_schemes_when_unknown_scheme_then_rejected_with_invalid_scheme() {
    let validator = DeepLinkValidator::new(&["myapp"]);
    let result = validator.validate("evil://steal-data");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        PlatformRejection::InvalidScheme
    ));
}

#[test]
fn given_any_config_when_javascript_scheme_then_rejected_with_dangerous_scheme() {
    let validator = DeepLinkValidator::new(&["myapp"]);
    let result = validator.validate("javascript:alert(1)");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        PlatformRejection::DangerousScheme
    ));
}

#[test]
fn given_any_config_when_data_uri_then_rejected_with_dangerous_scheme() {
    let validator = DeepLinkValidator::new(&["myapp"]);
    let result = validator.validate("data:text/html,<script>alert(1)</script>");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        PlatformRejection::DangerousScheme
    ));
}

#[test]
fn given_any_config_when_path_traversal_then_rejected() {
    let validator = DeepLinkValidator::new(&["myapp"]);
    let result = validator.validate("myapp://../../etc/passwd");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        PlatformRejection::PathTraversal
    ));
}

#[test]
fn given_allowed_hosts_when_matching_host_then_accepted() {
    let validator = DeepLinkValidator::new(&["https"]).with_allowed_hosts(&["example.com"]);
    let result = validator.validate("https://example.com/path");
    assert!(result.is_ok());
    assert_eq!(result.unwrap().as_inner(), "https://example.com/path");
}

#[test]
fn given_allowed_hosts_when_mismatched_host_then_rejected_with_untrusted_host() {
    let validator = DeepLinkValidator::new(&["https"]).with_allowed_hosts(&["example.com"]);
    let result = validator.validate("https://evil.com/path");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        PlatformRejection::UntrustedHost
    ));
}

// ── Feature: Clipboard Security Policy ───────────────────────────────────────

#[test]
fn given_confidential_data_when_policy_checked_then_restrict_to_local_device() {
    let policy = ClipboardPolicy::for_classification(DataClassification::Confidential);
    assert!(policy.restrict_to_local_device());
}

#[test]
fn given_secret_data_when_policy_checked_then_expiration_60_seconds() {
    let policy = ClipboardPolicy::for_classification(DataClassification::Secret);
    assert_eq!(policy.expiration_seconds(), Some(60));
}

#[test]
fn given_public_data_when_policy_checked_then_no_restrictions() {
    let policy = ClipboardPolicy::for_classification(DataClassification::Public);
    assert!(!policy.restrict_to_local_device());
    assert_eq!(policy.expiration_seconds(), None);
}

// ── Feature: WebView URL Safety ──────────────────────────────────────────────

#[test]
fn given_https_url_when_webview_validated_then_accepted() {
    let validator = WebViewUrlValidator::new();
    let result = validator.validate("https://trusted.com/page");
    assert!(result.is_ok());
    assert_eq!(result.unwrap().as_inner(), "https://trusted.com/page");
}

#[test]
fn given_file_url_when_webview_validated_then_rejected_with_file_access_blocked() {
    let validator = WebViewUrlValidator::new();
    let result = validator.validate("file:///etc/passwd");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        PlatformRejection::FileAccessBlocked
    ));
}

#[test]
fn given_javascript_url_when_webview_validated_then_rejected_with_dangerous_scheme() {
    let validator = WebViewUrlValidator::new();
    let result = validator.validate("javascript:void(0)");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        PlatformRejection::DangerousScheme
    ));
}

#[test]
fn given_data_url_when_webview_validated_then_rejected_with_dangerous_scheme() {
    let validator = WebViewUrlValidator::new();
    let result = validator.validate("data:text/html,<script>");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        PlatformRejection::DangerousScheme
    ));
}

#[test]
fn given_blob_url_when_webview_validated_then_rejected_with_dangerous_scheme() {
    let validator = WebViewUrlValidator::new();
    let result = validator.validate("blob:https://example.com/uuid");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        PlatformRejection::DangerousScheme
    ));
}

#[test]
fn given_domain_allowlist_when_matching_domain_then_accepted() {
    let validator = WebViewUrlValidator::new().with_allowed_domains(&["trusted.com"]);
    let result = validator.validate("https://trusted.com/page");
    assert!(result.is_ok());
}

#[test]
fn given_domain_allowlist_when_non_matching_domain_then_rejected() {
    let validator = WebViewUrlValidator::new().with_allowed_domains(&["trusted.com"]);
    let result = validator.validate("https://evil.com/page");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        PlatformRejection::UntrustedHost
    ));
}

// ── Feature: Screenshot Prevention Signal ────────────────────────────────────

#[test]
fn given_prevent_policy_when_checked_then_should_prevent() {
    let policy = ScreenshotPolicy::prevent();
    assert!(policy.should_prevent_screenshot());
}

#[test]
fn given_allow_policy_when_checked_then_should_not_prevent() {
    let policy = ScreenshotPolicy::allow();
    assert!(!policy.should_prevent_screenshot());
}

#[test]
fn given_no_explicit_policy_when_confidential_data_then_defaults_to_prevent() {
    let policy = ScreenshotPolicy::for_classification(DataClassification::Confidential);
    assert!(policy.should_prevent_screenshot());
}

#[test]
fn given_no_explicit_policy_when_public_data_then_defaults_to_allow() {
    let policy = ScreenshotPolicy::for_classification(DataClassification::Public);
    assert!(!policy.should_prevent_screenshot());
}

// ── Security event emission tests ────────────────────────────────────────────

#[test]
fn given_dangerous_deep_link_when_validated_then_security_event_emitted() {
    let validator = DeepLinkValidator::new(&["myapp"]);
    let (result, events) = validator.validate_with_events("javascript:alert(1)");
    assert!(result.is_err());
    assert!(!events.is_empty(), "security event should be emitted");
}

#[test]
fn given_dangerous_webview_url_when_validated_then_security_event_emitted() {
    let validator = WebViewUrlValidator::new();
    let (result, events) = validator.validate_with_events("file:///etc/passwd");
    assert!(result.is_err());
    assert!(!events.is_empty(), "security event should be emitted");
}

#[test]
fn given_valid_deep_link_when_validated_then_no_security_events() {
    let validator = DeepLinkValidator::new(&["myapp"]);
    let (result, events) = validator.validate_with_events("myapp://home");
    assert!(result.is_ok());
    assert!(events.is_empty(), "no events for valid input");
}
