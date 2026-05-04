//! Time-source abstraction for testable time-dependent logic.
//!
//! [`TimeSource`] is a **sealed trait** — only crate-internal implementations are permitted.
//! This prevents external crates from accidentally introducing untestable time dependencies.

use time::OffsetDateTime;

mod sealed {
    /// Sealing trait — prevents external implementations of [`super::TimeSource`].
    pub trait Sealed {}
}

/// An abstraction over time retrieval, enabling deterministic testing.
///
/// This trait is sealed — external crates cannot implement it.
pub trait TimeSource: sealed::Sealed {
    /// Returns the current time as an [`OffsetDateTime`].
    fn now(&self) -> OffsetDateTime;
}

/// A [`TimeSource`] that returns the real system time.
///
/// # Examples
///
/// ```
/// use security_core::time::{SystemTimeSource, TimeSource};
///
/// let ts = SystemTimeSource;
/// let now = ts.now();
/// // The returned time should be close to the true UTC time.
/// assert!(now.year() >= 2024);
/// ```
pub struct SystemTimeSource;

impl sealed::Sealed for SystemTimeSource {}

impl TimeSource for SystemTimeSource {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// A [`TimeSource`] that always returns a fixed, pre-set time.
///
/// Use in tests to make time-dependent logic deterministic.
///
/// # Examples
///
/// ```
/// use security_core::time::{MockTimeSource, TimeSource};
/// use time::OffsetDateTime;
///
/// let fixed = OffsetDateTime::UNIX_EPOCH;
/// let ts = MockTimeSource::new(fixed);
/// assert_eq!(ts.now(), fixed);
/// ```
pub struct MockTimeSource {
    fixed_time: OffsetDateTime,
}

impl MockTimeSource {
    /// Creates a new [`MockTimeSource`] that always returns `fixed_time`.
    #[must_use]
    pub fn new(fixed_time: OffsetDateTime) -> Self {
        Self { fixed_time }
    }
}

impl sealed::Sealed for MockTimeSource {}

impl TimeSource for MockTimeSource {
    fn now(&self) -> OffsetDateTime {
        self.fixed_time
    }
}
