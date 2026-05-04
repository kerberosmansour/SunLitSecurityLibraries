//! Security event emission interface.

use crate::event::SecurityEvent;

mod private {
    /// Sealing marker.
    pub trait Sealed {}
}

/// A sealed trait for types that can emit security events.
pub trait SecurityEventEmitter: private::Sealed {
    /// Emits a security event.
    fn emit(&self, event: SecurityEvent);
}

/// Emits a [`SecurityEvent`] via the `tracing` infrastructure.
///
/// The event is serialized to JSON and emitted at `INFO` level.
///
/// # Examples
///
/// ```
/// use security_events::emit::emit_security_event;
/// use security_events::event::{EventOutcome, SecurityEvent};
/// use security_events::kind::EventKind;
/// use security_core::severity::SecuritySeverity;
///
/// let event = SecurityEvent::new(
///     EventKind::AdminAction,
///     SecuritySeverity::Info,
///     EventOutcome::Success,
/// );
/// emit_security_event(event);
/// ```
pub fn emit_security_event(event: SecurityEvent) {
    match serde_json::to_string(&event) {
        Ok(json) => tracing::info!(security_event = %json, "security_event"),
        Err(e) => tracing::warn!("failed to serialize security event: {e}"),
    }
}

/// A default emitter that calls [`emit_security_event`].
pub struct DefaultEmitter;

impl private::Sealed for DefaultEmitter {}

impl SecurityEventEmitter for DefaultEmitter {
    fn emit(&self, event: SecurityEvent) {
        emit_security_event(event);
    }
}
