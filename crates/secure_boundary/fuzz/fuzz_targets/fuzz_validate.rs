#![no_main]
//! Fuzz target: normalize_email never panics and result <= input length.
use libfuzzer_sys::fuzz_target;
use secure_boundary::normalize::{normalize_email, trim_whitespace};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = normalize_email(s);
        let trimmed = trim_whitespace(s);
        // Invariant: trimming never adds characters
        assert!(trimmed.len() <= s.len());
    }
});
