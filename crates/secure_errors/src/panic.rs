//! Panic boundary — catches panics at the service boundary and returns a safe 500 response.
//!
//! Uses `std::panic::catch_unwind` (cross-platform). Does not rely on Unix signals.

use std::panic::UnwindSafe;

/// A marker type representing the panic-safe layer.
///
/// Satisfies `Clone + Send + Sync + 'static` tower bounds for use as middleware.
#[derive(Clone, Debug)]
pub struct PanicSafeLayer;

/// Executes `f` inside a panic boundary.
///
/// Returns:
/// - `(200, "ok")` if `f` completes normally (the return value is discarded).
/// - `(500, json_body)` if `f` panics — the JSON body contains only `"internal_error"`,
///   never the panic message.
///
/// # Examples
///
/// ```
/// use secure_errors::panic::catch_panic_to_safe_response;
///
/// let (status, _body) = catch_panic_to_safe_response(|| "all good");
/// assert_eq!(status, 200);
///
/// let (status, body) = catch_panic_to_safe_response(|| panic!("boom"));
/// assert_eq!(status, 500);
/// assert!(body.contains("internal_error"));
/// ```
pub fn catch_panic_to_safe_response<F, T>(f: F) -> (u16, String)
where
    F: FnOnce() -> T + UnwindSafe,
{
    match std::panic::catch_unwind(f) {
        Ok(_) => (200, r#"{"code":"ok","message":"ok"}"#.to_owned()),
        Err(_panic_payload) => {
            // Deliberately discard the panic payload — it must not appear in the response.
            let body = r#"{"code":"internal_error","message":"An internal error occurred."}"#;
            (500, body.to_owned())
        }
    }
}
