#![no_main]
//! Fuzz target: URL encoder never panics.
use libfuzzer_sys::fuzz_target;
use secure_output::encode::OutputEncoder;
use secure_output::url::UrlEncoder;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let enc = UrlEncoder;
        let _ = enc.encode(s);
    }
});
