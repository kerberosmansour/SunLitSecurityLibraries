//! Core security event schema.

use crate::kind::EventKind;
use security_core::classification::DataClassification;
use security_core::severity::SecuritySeverity;
use security_core::types::{RequestId, TenantId, TraceId};
use serde::Serialize;
use std::collections::BTreeMap;
use std::net::IpAddr;
use time::OffsetDateTime;
use uuid::Uuid;

/// The outcome of a security event.
///
/// # Examples
///
/// ```
/// use security_events::event::EventOutcome;
///
/// let outcome = EventOutcome::Success;
/// assert_eq!(outcome, EventOutcome::Success);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventOutcome {
    /// The operation succeeded.
    Success,
    /// The operation failed.
    Failure,
    /// The operation was blocked by a security control.
    Blocked,
    /// The outcome is unknown.
    Unknown,
}

/// A labeled value that carries its data classification.
///
/// # Examples
///
/// ```
/// use security_events::event::EventValue;
/// use security_core::classification::DataClassification;
///
/// let val = EventValue::Classified {
///     value: "user@example.com".to_string(),
///     classification: DataClassification::PII,
/// };
/// assert_eq!(format!("{val:?}").contains("PII"), true);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventValue {
    /// A classified data value.
    Classified {
        /// The raw or (post-redaction) string value.
        value: String,
        /// The data classification for this value.
        classification: DataClassification,
    },
}

/// A structured, serializable security audit event.
#[derive(Clone, Debug, Serialize)]
pub struct SecurityEvent {
    /// ISO-8601 timestamp of when the event occurred.
    pub timestamp: OffsetDateTime,
    /// Unique identifier for this event.
    pub event_id: Uuid,
    /// Optional identifier of the parent event for correlation and investigation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_event_id: Option<Uuid>,
    /// The kind of security event.
    pub kind: EventKind,
    /// Severity of this event.
    pub severity: SecuritySeverity,
    /// The outcome of the operation that triggered this event.
    pub outcome: EventOutcome,
    /// The actor (user/service) that triggered the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// The tenant context of this event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<TenantId>,
    /// The source IP address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<IpAddr>,
    /// The inbound request identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<RequestId>,
    /// The distributed trace identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<TraceId>,
    /// The session identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// The resource that was the target of the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// A stable reason code for this event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<&'static str>,
    /// Optional per-event HMAC-SHA256 signature for tamper evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac: Option<String>,
    /// Arbitrary labelled values associated with this event.
    pub labels: BTreeMap<String, EventValue>,
}

impl SecurityEvent {
    /// Creates a new [`SecurityEvent`] with the given kind, severity, and outcome.
    ///
    /// Sets `timestamp` to now (UTC) and generates a new random `event_id`.
    #[must_use]
    pub fn new(kind: EventKind, severity: SecuritySeverity, outcome: EventOutcome) -> Self {
        Self {
            timestamp: OffsetDateTime::now_utc(),
            event_id: Uuid::new_v4(),
            parent_event_id: None,
            kind,
            severity,
            outcome,
            actor: None,
            tenant: None,
            source_ip: None,
            request_id: None,
            trace_id: None,
            session_id: None,
            resource: None,
            reason_code: None,
            hmac: None,
            labels: BTreeMap::new(),
        }
    }

    /// Returns a copy of this event linked to `parent_event_id`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use security_core::severity::SecuritySeverity;
    /// use security_events::event::{EventOutcome, SecurityEvent};
    /// use security_events::kind::EventKind;
    /// use uuid::Uuid;
    ///
    /// let parent_id = Uuid::new_v4();
    /// let event = SecurityEvent::new(
    ///     EventKind::AdminAction,
    ///     SecuritySeverity::Info,
    ///     EventOutcome::Success,
    /// )
    /// .with_parent_event_id(parent_id);
    ///
    /// assert_eq!(event.parent_event_id, Some(parent_id));
    /// ```
    #[must_use]
    pub fn with_parent_event_id(mut self, parent_event_id: Uuid) -> Self {
        self.parent_event_id = Some(parent_event_id);
        self
    }
}
