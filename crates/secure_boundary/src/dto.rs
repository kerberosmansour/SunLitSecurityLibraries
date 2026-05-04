//! DTO marker trait for mass-assignment prevention.

/// Marker trait for Data Transfer Objects.
///
/// Implementing this trait signals that a type is an explicitly declared DTO
/// designed to prevent mass-assignment vulnerabilities. Types implementing
/// `SecureDto` should use `#[serde(deny_unknown_fields)]` and declare only
/// the fields they intentionally accept.
///
/// # Examples
///
/// ```
/// use secure_boundary::dto::SecureDto;
///
/// #[derive(serde::Deserialize)]
/// #[serde(deny_unknown_fields)]
/// struct CreateUser {
///     name: String,
/// }
///
/// impl SecureDto for CreateUser {}
/// ```
pub trait SecureDto: Send + Sync + 'static {}
