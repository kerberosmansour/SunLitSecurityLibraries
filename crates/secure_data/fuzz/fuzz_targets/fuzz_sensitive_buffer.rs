#![no_main]
//! Fuzz target: SensitiveBuffer lifecycle never panics on arbitrary bytes.
use libfuzzer_sys::fuzz_target;
use secure_data::mobile_storage::SensitiveBuffer;
use std::time::Duration;

fuzz_target!(|data: &[u8]| {
    // Test basic lifecycle
    let mut buf = SensitiveBuffer::new(data.to_vec());
    assert_eq!(buf.expose(), data);
    let _ = buf.is_expired();
    buf.wipe();
    assert!(buf.expose().is_empty() || buf.expose().iter().all(|&b| b == 0));

    // Test with TTL
    if data.len() >= 2 {
        let ttl_secs = u64::from(data[0]);
        let buf2 = SensitiveBuffer::with_ttl(data.to_vec(), Duration::from_secs(ttl_secs));
        let _ = buf2.expose();
        let _ = buf2.is_expired();
    }
});
