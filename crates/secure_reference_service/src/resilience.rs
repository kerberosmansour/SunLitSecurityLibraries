//! Resilience patterns — timeouts, concurrency limits (bulkhead).
//!
//! These are thin wrappers around `tower` and `tower-http` primitives.
//! The request timeout and concurrency limit are configured here.

use std::time::Duration;

/// Default request timeout.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Default concurrency limit (bulkhead).
pub const DEFAULT_CONCURRENCY_LIMIT: usize = 100;

/// Configuration for resilience patterns.
#[derive(Debug, Clone)]
pub struct ResilienceConfig {
    /// Request-level timeout.
    pub request_timeout: Duration,
    /// Maximum concurrent in-flight requests (bulkhead).
    pub concurrency_limit: usize,
}

impl Default for ResilienceConfig {
    fn default() -> Self {
        Self {
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            concurrency_limit: DEFAULT_CONCURRENCY_LIMIT,
        }
    }
}

impl ResilienceConfig {
    /// Creates a new `ResilienceConfig` with the given timeout and concurrency limit.
    #[must_use]
    pub fn new(request_timeout: Duration, concurrency_limit: usize) -> Self {
        Self {
            request_timeout,
            concurrency_limit,
        }
    }
}
