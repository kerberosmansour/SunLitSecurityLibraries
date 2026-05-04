//! Panic test route — used in integration tests to verify the panic boundary catches panics.
//!
//! This route intentionally panics when called. It is only included in test/dev builds.

/// `GET /panic-test` — intentionally panics to verify the panic boundary.
///
/// This route MUST NOT exist in production.
pub async fn panic_test() -> http::StatusCode {
    panic!("intentional test panic — PanicSafeLayer must catch this");
}
