//! Backtrace capture and context attachment helpers.
//!
//! Provides utilities for attaching diagnostic context to error reports.
//! Backtrace capture is best-effort — available only when `RUST_BACKTRACE=1`
//! is set in the environment.

/// Captures the current backtrace as a string, if backtraces are enabled.
///
/// Returns `Some(backtrace_string)` when `RUST_BACKTRACE` is set, `None` otherwise.
///
/// # Examples
///
/// ```
/// use secure_errors::capture::capture_backtrace;
///
/// // Returns None when RUST_BACKTRACE is not set.
/// let bt = capture_backtrace();
/// // bt is either Some("...") or None depending on environment.
/// ```
#[must_use]
pub fn capture_backtrace() -> Option<String> {
    let bt = std::backtrace::Backtrace::capture();
    match bt.status() {
        std::backtrace::BacktraceStatus::Captured => Some(bt.to_string()),
        _ => None,
    }
}

/// Attaches a key-value context entry to an existing cause string.
///
/// This helper appends `key=value` pairs to the internal cause text so that
/// forensic context accumulates on the `ErrorReport` without leaking into
/// the public response.
///
/// # Examples
///
/// ```
/// use secure_errors::capture::attach_context;
///
/// let cause = "query failed";
/// let enriched = attach_context(cause, "table", "users");
/// assert_eq!(enriched, "query failed [table=users]");
/// ```
#[must_use]
pub fn attach_context(cause: &str, key: &str, value: &str) -> String {
    format!("{cause} [{key}={value}]")
}
