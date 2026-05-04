//! Configurable request limits to prevent resource exhaustion.

/// Configurable limits for request parsing and validation.
///
/// Used to prevent resource exhaustion attacks (oversized bodies, excessive field
/// counts, deeply nested JSON structures).
///
/// # Examples
///
/// ```
/// use secure_boundary::limits::RequestLimits;
///
/// let limits = RequestLimits::new()
///     .with_max_body_bytes(512 * 1024)
///     .with_max_nesting_depth(5);
/// assert_eq!(limits.max_body_bytes, 512 * 1024);
/// assert_eq!(limits.max_nesting_depth, 5);
/// ```
#[derive(Clone, Debug)]
pub struct RequestLimits {
    /// Maximum allowed body size in bytes. Default: 1 MiB.
    pub max_body_bytes: usize,
    /// Maximum number of top-level fields in a request. Default: 100.
    pub max_field_count: usize,
    /// Maximum nesting depth for nested structures. Default: 10.
    pub max_nesting_depth: usize,
}

impl Default for RequestLimits {
    fn default() -> Self {
        Self {
            max_body_bytes: 1024 * 1024, // 1 MiB
            max_field_count: 100,
            max_nesting_depth: 10,
        }
    }
}

impl RequestLimits {
    /// Creates a new [`RequestLimits`] with OWASP-recommended defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Overrides the maximum body size in bytes.
    #[must_use]
    pub fn with_max_body_bytes(mut self, max: usize) -> Self {
        self.max_body_bytes = max;
        self
    }

    /// Overrides the maximum field count.
    #[must_use]
    pub fn with_max_field_count(mut self, max: usize) -> Self {
        self.max_field_count = max;
        self
    }

    /// Overrides the maximum nesting depth.
    #[must_use]
    pub fn with_max_nesting_depth(mut self, max: usize) -> Self {
        self.max_nesting_depth = max;
        self
    }
}
