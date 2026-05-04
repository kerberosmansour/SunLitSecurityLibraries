// Safe serialization helpers for secret-bearing structs.
//
// Re-exports the `redact` serializer function and the `RedactedField` marker type.

use serde::Serializer;

/// Serializes any field as the literal string `"[REDACTED]"`.
///
/// Intended for use with `#[serde(serialize_with = "secure_data::serde::redact")]`.
///
/// # Examples
///
/// ```
/// #[derive(serde::Serialize)]
/// struct MyStruct {
///     #[serde(serialize_with = "secure_data::serde::redact")]
///     secret: String,
/// }
///
/// let s = MyStruct { secret: "hunter2".into() };
/// let json = serde_json::to_string(&s).unwrap();
/// assert!(json.contains("REDACTED"));
/// assert!(!json.contains("hunter2"));
/// ```
///
/// # Errors
/// Propagates serializer errors from the underlying format.
pub fn redact<S: Serializer>(
    _value: &impl serde::Serialize,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str("[REDACTED]")
}

/// A zero-size marker type whose [`serde::Serialize`] impl always emits `"[REDACTED]"`.
///
/// Useful as a field type when the actual secret is stored elsewhere.
///
/// # Examples
///
/// ```
/// use secure_data::serde::RedactedField;
///
/// let field = RedactedField;
/// let json = serde_json::to_string(&field).unwrap();
/// assert_eq!(json, r#""[REDACTED]""#);
/// ```
#[derive(Debug, Clone, Default)]
pub struct RedactedField;

impl serde::Serialize for RedactedField {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("[REDACTED]")
    }
}
