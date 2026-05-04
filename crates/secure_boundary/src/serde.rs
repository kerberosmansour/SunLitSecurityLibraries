//! Strict deserialization that rejects unknown fields.

use ::serde::de::DeserializeOwned;

/// A wrapper for strict deserialization of JSON into `T`.
///
/// Use [`StrictDeserialize::from_json`] to parse JSON bytes. For full protection
/// against mass-assignment, annotate `T` with `#[serde(deny_unknown_fields)]`.
pub struct StrictDeserialize<T>(std::marker::PhantomData<T>);

impl<T: DeserializeOwned> StrictDeserialize<T> {
    /// Deserializes JSON from `data` into `T`.
    ///
    /// Callers **must** ensure `T` uses `#[serde(deny_unknown_fields)]` to
    /// fully prevent mass-assignment via unknown fields.
    ///
    /// # Errors
    /// Returns an error string describing the parse or validation failure.
    pub fn from_json(data: &[u8]) -> Result<T, String> {
        serde_json::from_slice(data).map_err(|e| e.to_string())
    }
}
