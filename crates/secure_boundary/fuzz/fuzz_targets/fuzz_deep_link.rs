#![no_main]
//! Fuzz target: DeepLinkValidator::validate never panics on arbitrary URLs.
use libfuzzer_sys::fuzz_target;
use secure_boundary::platform::DeepLinkValidator;

fuzz_target!(|data: &[u8]| {
    if let Ok(url) = std::str::from_utf8(data) {
        let validator = DeepLinkValidator::new(&["myapp", "https", "http"]);
        let _ = validator.validate(url);
    }
});
