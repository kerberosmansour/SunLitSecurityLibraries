#![no_main]
//! Fuzz target: WebViewUrlValidator::validate never panics on arbitrary URLs.
use libfuzzer_sys::fuzz_target;
use secure_boundary::platform::WebViewUrlValidator;

fuzz_target!(|data: &[u8]| {
    if let Ok(url) = std::str::from_utf8(data) {
        let validator = WebViewUrlValidator::new()
            .with_allowed_domains(&["example.com", "trusted.org"]);
        let _ = validator.validate(url);
    }
});
