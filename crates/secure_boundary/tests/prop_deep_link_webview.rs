//! Property tests — deep link and WebView URL validation invariants.
//!
//! Milestone 9 — BDD: Mobile platform safety properties.
#![cfg(feature = "mobile-platform")]
use proptest::prelude::*;
use secure_boundary::platform::{DeepLinkValidator, PlatformRejection, WebViewUrlValidator};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// No javascript:, data:, or vbscript: URL ever produces a valid SafeDeepLink.
    #[test]
    fn prop_deep_link_rejects_dangerous_schemes(
        scheme in prop_oneof!["javascript", "data", "vbscript", "blob"],
        payload in "[a-zA-Z0-9:;,=/]{0,50}",
    ) {
        let url = format!("{scheme}:{payload}");
        let validator = DeepLinkValidator::new(&["myapp", "https"]);
        let result = validator.validate(&url);
        prop_assert!(
            result.is_err(),
            "Dangerous scheme should always be rejected",
        );
        if let Err(e) = result {
            prop_assert_eq!(
                e,
                PlatformRejection::DangerousScheme,
                "Expected DangerousScheme rejection",
            );
        }
    }

    /// No file:// URL ever produces a valid SafeWebViewUrl.
    #[test]
    fn prop_webview_url_rejects_file_urls(path in "[a-zA-Z0-9/._-]{0,50}") {
        let url = format!("file://{path}");
        let validator = WebViewUrlValidator::new()
            .with_allowed_domains(&["example.com"]);
        let result = validator.validate(&url);
        prop_assert!(
            result.is_err(),
            "file:// URL should always be rejected by WebViewUrlValidator",
        );
    }

    /// DeepLinkValidator::validate never panics on arbitrary input.
    #[test]
    fn prop_deep_link_validate_no_panic(url in ".*") {
        let validator = DeepLinkValidator::new(&["myapp", "https"]);
        let _ = validator.validate(&url);
    }

    /// WebViewUrlValidator::validate never panics on arbitrary input.
    #[test]
    fn prop_webview_validate_no_panic(url in ".*") {
        let validator = WebViewUrlValidator::new()
            .with_allowed_domains(&["example.com"]);
        let _ = validator.validate(&url);
    }
}
