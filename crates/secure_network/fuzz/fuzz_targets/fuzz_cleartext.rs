#![no_main]
//! Fuzz target: CleartextDetector::check never panics on arbitrary URLs.
use libfuzzer_sys::fuzz_target;
use secure_network::{CleartextDetector, CleartextResult};

fuzz_target!(|data: &[u8]| {
    if let Ok(url) = std::str::from_utf8(data) {
        let detector = CleartextDetector::new().with_localhost_exemption(true);
        let result = detector.check(url);
        // Invariant: http:// URLs should never be Secure
        if url.to_ascii_lowercase().starts_with("http://") {
            assert_ne!(result, CleartextResult::Secure);
        }
    }
});
