//! Event correlation helpers for linking related security events.

use crate::event::SecurityEvent;
use uuid::Uuid;

/// Returns `event` linked to `parent_event_id`.
///
/// # Examples
///
/// ```rust
/// use security_core::severity::SecuritySeverity;
/// use security_events::correlation::with_parent;
/// use security_events::event::{EventOutcome, SecurityEvent};
/// use security_events::kind::EventKind;
/// use uuid::Uuid;
///
/// let parent_id = Uuid::new_v4();
/// let child = with_parent(
///     SecurityEvent::new(
///         EventKind::AuthzDeny,
///         SecuritySeverity::Medium,
///         EventOutcome::Blocked,
///     ),
///     parent_id,
/// );
///
/// assert_eq!(child.parent_event_id, Some(parent_id));
/// ```
#[must_use]
pub fn with_parent(mut event: SecurityEvent, parent_event_id: Uuid) -> SecurityEvent {
    event.parent_event_id = Some(parent_event_id);
    event
}

/// Attaches a `parent_event_id` to an existing event in place.
///
/// # Examples
///
/// ```rust
/// use security_core::severity::SecuritySeverity;
/// use security_events::correlation::attach_parent;
/// use security_events::event::{EventOutcome, SecurityEvent};
/// use security_events::kind::EventKind;
/// use uuid::Uuid;
///
/// let parent_id = Uuid::new_v4();
/// let mut child = SecurityEvent::new(
///     EventKind::AuthzDeny,
///     SecuritySeverity::Medium,
///     EventOutcome::Blocked,
/// );
/// attach_parent(&mut child, parent_id);
/// assert_eq!(child.parent_event_id, Some(parent_id));
/// ```
pub fn attach_parent(event: &mut SecurityEvent, parent_event_id: Uuid) {
    event.parent_event_id = Some(parent_event_id);
}

/// Returns the subset of `events` that reference `parent_event_id`.
///
/// # Examples
///
/// ```rust
/// use security_core::severity::SecuritySeverity;
/// use security_events::correlation::{filter_by_parent, with_parent};
/// use security_events::event::{EventOutcome, SecurityEvent};
/// use security_events::kind::EventKind;
/// use uuid::Uuid;
///
/// let parent_id = Uuid::new_v4();
/// let child = with_parent(
///     SecurityEvent::new(
///         EventKind::AuthzDeny,
///         SecuritySeverity::Medium,
///         EventOutcome::Blocked,
///     ),
///     parent_id,
/// );
/// let events = vec![child];
/// assert_eq!(filter_by_parent(&events, parent_id).len(), 1);
/// ```
#[must_use]
pub fn filter_by_parent(events: &[SecurityEvent], parent_event_id: Uuid) -> Vec<&SecurityEvent> {
    events
        .iter()
        .filter(|event| event.parent_event_id == Some(parent_event_id))
        .collect()
}
