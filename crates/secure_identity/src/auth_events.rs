//! Authentication success/failure event helpers.

use std::net::IpAddr;

use security_core::classification::DataClassification;
use security_core::severity::SecuritySeverity;
use security_events::event::{EventOutcome, EventValue, SecurityEvent};
use security_events::kind::EventKind;
use security_events::sink::SecuritySink;

/// Context attached to authentication audit events.
#[derive(Debug, Clone)]
pub struct AuthEventContext {
    /// Stable user identifier.
    pub user_id: String,
    /// Authentication method (for example `jwt`, `totp`, `api_key`).
    pub method: String,
    /// Source IP address, if available.
    pub source_ip: Option<IpAddr>,
    /// User-Agent header value, if available.
    pub user_agent: Option<String>,
}

/// A sink-backed emitter for authentication events.
pub struct AuthEventEmitter<S: SecuritySink> {
    sink: S,
}

impl<S: SecuritySink> AuthEventEmitter<S> {
    /// Creates a new emitter writing to the provided sink.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_identity::auth_events::AuthEventEmitter;
    /// use security_events::sink::InMemorySink;
    ///
    /// let emitter = AuthEventEmitter::new(InMemorySink::new());
    /// let _ = emitter;
    /// ```
    #[must_use]
    pub fn new(sink: S) -> Self {
        Self { sink }
    }

    /// Emits an authentication success event.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_identity::auth_events::{AuthEventContext, AuthEventEmitter};
    /// use security_events::sink::InMemorySink;
    ///
    /// let emitter = AuthEventEmitter::new(InMemorySink::new());
    /// emitter.emit_success(AuthEventContext {
    ///     user_id: "user-1".to_string(),
    ///     method: "jwt".to_string(),
    ///     source_ip: None,
    ///     user_agent: None,
    /// });
    /// ```
    pub fn emit_success(&self, context: AuthEventContext) {
        let event = build_success_event(context);
        self.sink.write_event(&event);
    }

    /// Emits an authentication failure event with a stable reason code.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_identity::auth_events::{AuthEventContext, AuthEventEmitter};
    /// use security_events::sink::InMemorySink;
    ///
    /// let emitter = AuthEventEmitter::new(InMemorySink::new());
    /// emitter.emit_failure(
    ///     AuthEventContext {
    ///         user_id: "user-1".to_string(),
    ///         method: "jwt".to_string(),
    ///         source_ip: None,
    ///         user_agent: None,
    ///     },
    ///     "invalid_credentials",
    /// );
    /// ```
    pub fn emit_failure(&self, context: AuthEventContext, reason_code: &'static str) {
        let mut event = build_failure_event(context);
        event.reason_code = Some(reason_code);
        self.sink.write_event(&event);
    }
}

/// Builds an authentication success event.
///
/// # Examples
///
/// ```rust
/// use secure_identity::auth_events::{build_success_event, AuthEventContext};
///
/// let event = build_success_event(AuthEventContext {
///     user_id: "user-1".to_string(),
///     method: "jwt".to_string(),
///     source_ip: None,
///     user_agent: None,
/// });
/// assert_eq!(event.actor.as_deref(), Some("user-1"));
/// ```
#[must_use]
pub fn build_success_event(context: AuthEventContext) -> SecurityEvent {
    let mut event = SecurityEvent::new(
        EventKind::MfaEvent,
        SecuritySeverity::Info,
        EventOutcome::Success,
    );
    event.actor = Some(context.user_id);
    event.source_ip = context.source_ip;

    event.labels.insert(
        "auth_method".to_string(),
        EventValue::Classified {
            value: context.method,
            classification: DataClassification::Internal,
        },
    );

    if let Some(user_agent) = context.user_agent {
        event.labels.insert(
            "user_agent".to_string(),
            EventValue::Classified {
                value: user_agent,
                classification: DataClassification::Internal,
            },
        );
    }

    event
}

/// Builds an authentication failure event.
///
/// # Examples
///
/// ```rust
/// use secure_identity::auth_events::{build_failure_event, AuthEventContext};
///
/// let event = build_failure_event(AuthEventContext {
///     user_id: "user-1".to_string(),
///     method: "jwt".to_string(),
///     source_ip: None,
///     user_agent: None,
/// });
/// assert_eq!(event.actor.as_deref(), Some("user-1"));
/// ```
#[must_use]
pub fn build_failure_event(context: AuthEventContext) -> SecurityEvent {
    let mut event = SecurityEvent::new(
        EventKind::AuthnFailure,
        SecuritySeverity::High,
        EventOutcome::Failure,
    );
    event.actor = Some(context.user_id);
    event.source_ip = context.source_ip;

    event.labels.insert(
        "auth_method".to_string(),
        EventValue::Classified {
            value: context.method,
            classification: DataClassification::Internal,
        },
    );

    if let Some(user_agent) = context.user_agent {
        event.labels.insert(
            "user_agent".to_string(),
            EventValue::Classified {
                value: user_agent,
                classification: DataClassification::Internal,
            },
        );
    }

    event
}
