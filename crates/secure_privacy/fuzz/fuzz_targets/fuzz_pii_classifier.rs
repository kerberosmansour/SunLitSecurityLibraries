#![no_main]
//! Fuzz target: PiiClassifier::classify never panics on arbitrary strings.
use libfuzzer_sys::fuzz_target;
use secure_privacy::PiiClassifier;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let classifier = PiiClassifier::new();
        let _ = classifier.classify(s);
    }
});
