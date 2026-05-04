// Zeroization and read-once memory safety helpers.

pub use zeroize::Zeroizing;

use std::cell::Cell;

/// A wrapper that exposes its inner value exactly once, then zeroes it.
///
/// - `!Clone` — prevents duplicating the access slot.
/// - `!Copy` — enforced by `Drop` impl.
/// - `!Sync` — because the internal `Cell` is `!Sync`, preventing shared-reference access
///   from multiple threads simultaneously.
///
/// Call `take()` to extract the value; subsequent calls return `None`.
///
/// # Examples
///
/// ```
/// use secure_data::memory::ReadOnce;
///
/// let mut once = ReadOnce::new(vec![0x42u8; 32]);
/// assert!(once.take().is_some());
/// assert!(once.take().is_none()); // second call returns None
/// ```
pub struct ReadOnce<T: zeroize::Zeroize> {
    inner: Option<T>,
    taken: Cell<bool>,
}

impl<T: zeroize::Zeroize> ReadOnce<T> {
    /// Creates a new `ReadOnce` wrapper.
    #[must_use]
    pub fn new(value: T) -> Self {
        Self {
            inner: Some(value),
            taken: Cell::new(false),
        }
    }

    /// Extracts the inner value exactly once.
    ///
    /// Returns `Some(value)` on the first call, `None` on all subsequent calls.
    pub fn take(&mut self) -> Option<T> {
        if self.taken.get() {
            return None;
        }
        self.taken.set(true);
        self.inner.take()
    }
}

impl<T: zeroize::Zeroize> Drop for ReadOnce<T> {
    fn drop(&mut self) {
        if let Some(mut value) = self.inner.take() {
            value.zeroize();
        }
    }
}

impl<T: zeroize::Zeroize + std::fmt::Debug> std::fmt::Debug for ReadOnce<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.taken.get() {
            write!(f, "ReadOnce(<consumed>)")
        } else {
            write!(f, "ReadOnce(<available>)")
        }
    }
}
