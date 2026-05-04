//! `SecurityIncident` trait — sealed to types within the security crate family.
//!
//! Downstream crates implement this trait to emit security signals. The actual
//! event emission is wired in M3 (`security_events`). Here we define the contract.

use security_core::severity::SecuritySeverity;

/// Sealing module — only types in crates that can name `private::Sealed`
/// may implement `SecurityIncident`.
mod private {
    /// Marker trait for the sealed-trait pattern.
    pub trait Sealed {}
}

/// A trait for errors that represent potential security incidents.
///
/// This trait is **sealed** — only types from within the security crate family
/// may implement it, preventing uncontrolled third-party implementations.
///
/// The actual event emission is wired in M3 (`security_events`).
pub trait SecurityIncident: private::Sealed {
    /// Returns a stable, human-readable fingerprint for the incident type.
    ///
    /// Used for deduplication and alerting suppression. Must not contain
    /// runtime-variable data (e.g. user IDs, timestamps).
    fn incident_fingerprint(&self) -> &'static str;

    /// Returns the severity at which this incident should be escalated.
    fn alert_severity(&self) -> SecuritySeverity;

    /// Returns `true` if this error should trigger a security signal.
    fn security_signal(&self) -> bool;
}

/// Implement `SecurityIncident` for `AppError`.
use crate::kind::AppError;

impl private::Sealed for AppError {}

impl SecurityIncident for AppError {
    fn incident_fingerprint(&self) -> &'static str {
        match self {
            AppError::Validation { .. } => "validation_error",
            AppError::Forbidden { .. } => "access_denied",
            AppError::NotFound => "not_found",
            AppError::Conflict => "conflict",
            AppError::Dependency { .. } => "dependency_failure",
            AppError::Crypto => "crypto_failure",
            AppError::Internal => "internal_error",
            AppError::RateLimit { .. } => "rate_limit_exceeded",
        }
    }

    fn alert_severity(&self) -> SecuritySeverity {
        match self {
            AppError::Forbidden { .. } | AppError::Crypto => SecuritySeverity::High,
            AppError::Dependency { .. } | AppError::Internal => SecuritySeverity::Medium,
            AppError::RateLimit { .. } => SecuritySeverity::Low,
            _ => SecuritySeverity::Info,
        }
    }

    fn security_signal(&self) -> bool {
        matches!(self, AppError::Forbidden { .. } | AppError::Crypto)
    }
}

/// Emits a [`security_events::event::SecurityEvent`] for the given [`AppError`].
///
/// Maps `Forbidden` → [`security_events::kind::EventKind::AuthzDeny`] and
/// `Dependency` → [`security_events::kind::EventKind::ErrorEscalation`].
pub fn emit_event_for_incident(error: &AppError) {
    use security_events::emit::emit_security_event;
    use security_events::event::{EventOutcome, SecurityEvent};
    use security_events::kind::EventKind;

    let maybe_event = match error {
        AppError::Forbidden { .. } => Some(SecurityEvent::new(
            EventKind::AuthzDeny,
            error.alert_severity(),
            EventOutcome::Blocked,
        )),
        AppError::Dependency { .. } => Some(SecurityEvent::new(
            EventKind::ErrorEscalation,
            error.alert_severity(),
            EventOutcome::Failure,
        )),
        _ => None,
    };

    if let Some(event) = maybe_event {
        emit_security_event(event);
    }
}
