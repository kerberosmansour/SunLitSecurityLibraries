//! Secure validation trait and context.

/// Type-state marker: transport layer has been validated.
pub struct TransportValid;

/// Type-state marker: syntactic validity has been confirmed.
pub struct SyntaxValid;

/// Type-state marker: semantic validity has been confirmed.
pub struct SemanticsValid;

/// Context passed to validation methods, carrying request metadata.
///
/// # Examples
///
/// ```
/// use secure_boundary::validate::ValidationContext;
///
/// let ctx = ValidationContext::new();
/// assert!(ctx.path.is_none());
/// ```
#[derive(Clone, Debug, Default)]
pub struct ValidationContext {
    /// The request path, if available.
    pub path: Option<String>,
    /// The remote IP address, if available.
    pub source_ip: Option<std::net::IpAddr>,
}

impl ValidationContext {
    /// Creates a new empty [`ValidationContext`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Open trait for structured input validation.
///
/// Consumers implement this on their DTOs to participate in the four-stage
/// validation pipeline inside axum extractors:
/// 1. Transport validity (content-type, body size) — handled by extractors
/// 2. Syntactic validity — [`SecureValidate::validate_syntax`]
/// 3. Semantic validity — [`SecureValidate::validate_semantics`]
///
/// This trait is intentionally **open** — external crates must implement it.
///
/// # Examples
///
/// ```
/// use secure_boundary::validate::{SecureValidate, ValidationContext};
///
/// struct RegisterDto {
///     username: String,
/// }
///
/// impl SecureValidate for RegisterDto {
///     fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
///         if self.username.is_empty() {
///             return Err("username_empty");
///         }
///         Ok(())
///     }
///
///     fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
///         Ok(())
///     }
/// }
///
/// let dto = RegisterDto { username: "alice".into() };
/// let ctx = ValidationContext::new();
/// assert!(dto.validate_syntax(&ctx).is_ok());
/// ```
pub trait SecureValidate: Sized {
    /// Validates syntactic constraints: field types, required fields, length limits.
    ///
    /// Called before semantic validation in the pipeline.
    ///
    /// # Errors
    /// Returns a stable internal reason code on validation failure.
    fn validate_syntax(&self, ctx: &ValidationContext) -> Result<(), &'static str>;

    /// Validates semantic constraints: business rules, cross-field invariants.
    ///
    /// Called after syntactic validation succeeds.
    ///
    /// # Errors
    /// Returns a stable internal reason code on validation failure.
    fn validate_semantics(&self, ctx: &ValidationContext) -> Result<(), &'static str>;
}
