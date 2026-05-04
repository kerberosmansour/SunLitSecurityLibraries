//! Per-kind rate limiting for security event emission.

use crate::kind::EventKind;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// A token-bucket style rate limiter for security events, keyed by [`EventKind`].
///
/// # Examples
///
/// ```
/// use security_events::rate_limit::RateLimiter;
/// use security_events::kind::EventKind;
///
/// let limiter = RateLimiter::new(5, 60);
/// assert!(limiter.should_allow(&EventKind::AuthnFailure));
/// ```
pub struct RateLimiter {
    max_per_window: u32,
    window_seconds: u64,
    counters: Mutex<HashMap<String, (u32, Instant)>>,
}

impl RateLimiter {
    /// Creates a new [`RateLimiter`] with the given window size and maximum count.
    #[must_use]
    pub fn new(max_per_window: u32, window_seconds: u64) -> Self {
        Self {
            max_per_window,
            window_seconds,
            counters: Mutex::new(HashMap::new()),
        }
    }

    /// Returns `true` if the event of this `kind` is within the rate limit.
    ///
    /// Different [`EventKind`]s are tracked independently.
    #[must_use]
    pub fn should_allow(&self, kind: &EventKind) -> bool {
        let key = format!("{kind:?}");
        let mut map = self.counters.lock().expect("mutex poisoned");
        let now = Instant::now();
        let entry = map.entry(key).or_insert((0, now));
        if entry.1.elapsed().as_secs() >= self.window_seconds {
            *entry = (0, now);
        }
        if entry.0 < self.max_per_window {
            entry.0 += 1;
            true
        } else {
            false
        }
    }

    /// Resets all rate-limit counters.
    pub fn reset(&self) {
        let mut map = self.counters.lock().expect("mutex poisoned");
        map.clear();
    }
}
