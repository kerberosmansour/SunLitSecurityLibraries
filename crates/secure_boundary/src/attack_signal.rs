//! Boundary violation detection and security event emission.

use security_core::severity::SecuritySeverity;
use security_events::{
    emit::emit_security_event,
    event::{EventOutcome, SecurityEvent},
    kind::EventKind,
};

/// The category of boundary violation detected.
///
/// This enum is `#[non_exhaustive]` — new variants may be added in future minor versions.
///
/// # Examples
///
/// ```
/// use secure_boundary::attack_signal::ViolationKind;
///
/// let kind = ViolationKind::BodyTooLarge;
/// assert_eq!(kind, ViolationKind::BodyTooLarge);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ViolationKind {
    /// An unknown field was present in the request body.
    UnknownField,
    /// The request body exceeded the configured size limit.
    BodyTooLarge,
    /// The `Content-Type` header was missing or disallowed.
    InvalidContentType,
    /// A field failed syntactic validation.
    SyntaxViolation,
    /// A field failed semantic validation.
    SemanticViolation,
    /// The nesting depth exceeded the configured limit.
    NestingTooDeep,
    /// The field count exceeded the configured limit.
    TooManyFields,
    /// A path parameter failed validation.
    InvalidPathParam,
    /// A query parameter failed validation.
    InvalidQueryParam,
}

/// A boundary violation detected during request processing.
///
/// Call [`BoundaryViolation::emit`] to record it as a [`SecurityEvent`].
///
/// # Examples
///
/// ```
/// use secure_boundary::attack_signal::{BoundaryViolation, ViolationKind};
///
/// let violation = BoundaryViolation::new(ViolationKind::BodyTooLarge, "body_too_large");
/// assert_eq!(violation.kind, ViolationKind::BodyTooLarge);
/// assert_eq!(violation.reason_code, "body_too_large");
/// ```
#[derive(Clone, Debug)]
pub struct BoundaryViolation {
    /// The category of violation detected.
    pub kind: ViolationKind,
    /// A stable reason code for this violation.
    pub reason_code: &'static str,
}

impl BoundaryViolation {
    /// Creates a new [`BoundaryViolation`].
    #[must_use]
    pub fn new(kind: ViolationKind, reason_code: &'static str) -> Self {
        Self { kind, reason_code }
    }

    /// Emits this violation as a [`SecurityEvent`] via the security events subsystem.
    pub fn emit(&self) {
        let event = SecurityEvent::new(
            EventKind::BoundaryViolation,
            SecuritySeverity::Medium,
            EventOutcome::Blocked,
        );
        emit_security_event(event);
    }
}
