#![no_main]
//! Fuzz target: normalize never panics on arbitrary UTF-8 input.
use libfuzzer_sys::fuzz_target;
use secure_boundary::normalize::{normalize, to_nfc};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = to_nfc(s);
        let _ = normalize(s, false);
        let _ = normalize(s, true);
    }
});
