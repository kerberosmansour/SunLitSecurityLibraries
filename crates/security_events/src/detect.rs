//! AppSensor-style detection points for anomaly escalation.

use crate::event::{EventOutcome, SecurityEvent};
use crate::kind::EventKind;
use security_core::severity::SecuritySeverity;
use std::collections::HashMap;
use std::sync::Mutex;

/// Named detection points aligned with the OWASP AppSensor specification.
///
/// # Examples
///
/// ```
/// use security_events::detect::DetectionPoint;
///
/// let point = DetectionPoint::AuthzDenied;
/// assert_eq!(point, DetectionPoint::AuthzDenied);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DetectionPoint {
    /// Input was outside the expected range or schema.
    InputOutOfRange,
    /// An authorization denial was recorded.
    AuthzDenied,
    /// Multiple deserialization failures were observed.
    RepeatedDeserializerFailure,
    /// A cross-tenant resource probe was attempted.
    CrossTenantProbe,
    /// Repeated failed authentication indicating brute force.
    BruteForceAttempt,
}

/// Tracks per-actor security event counts and fires escalation events when thresholds are exceeded.
///
/// # Examples
///
/// ```
/// use security_events::detect::DetectionEngine;
///
/// let engine = DetectionEngine::new(3, 60);
/// // First few denials are within threshold.
/// assert!(engine.record_authz_denied("user-1").is_none());
/// ```
pub struct DetectionEngine {
    threshold: u32,
    window_seconds: u64,
    counters: Mutex<HashMap<String, (u32, std::time::Instant)>>,
}

impl DetectionEngine {
    /// Creates a new [`DetectionEngine`] with the given `threshold` and `window_seconds`.
    #[must_use]
    pub fn new(threshold: u32, window_seconds: u64) -> Self {
        Self {
            threshold,
            window_seconds,
            counters: Mutex::new(HashMap::new()),
        }
    }

    /// Records an authorization denial for `actor`.
    ///
    /// Returns a [`SecurityEvent`] if the actor's count exceeds the threshold within the window.
    #[must_use]
    pub fn record_authz_denied(&self, actor: &str) -> Option<SecurityEvent> {
        let mut map = self.counters.lock().expect("mutex poisoned");
        let now = std::time::Instant::now();
        let entry = map.entry(actor.to_string()).or_insert((0, now));
        if entry.1.elapsed().as_secs() > self.window_seconds {
            *entry = (0, now);
        }
        entry.0 += 1;
        if entry.0 > self.threshold {
            let mut event = SecurityEvent::new(
                EventKind::AuthzDeny,
                SecuritySeverity::Critical,
                EventOutcome::Blocked,
            );
            event.actor = Some(actor.to_string());
            event.reason_code = Some("brute_force_detected");
            Some(event)
        } else {
            None
        }
    }

    /// Records a cross-tenant probe attempt and always returns a Critical [`SecurityEvent`].
    #[must_use]
    pub fn record_cross_tenant_probe(
        &self,
        actor: &str,
        actor_tenant: &str,
        resource_tenant: &str,
    ) -> SecurityEvent {
        let mut event = SecurityEvent::new(
            EventKind::CrossTenantAttempt,
            SecuritySeverity::Critical,
            EventOutcome::Blocked,
        );
        event.actor = Some(actor.to_string());
        event.reason_code = Some("cross_tenant_probe");
        event.labels.insert(
            "actor_tenant".to_string(),
            crate::event::EventValue::Classified {
                value: actor_tenant.to_string(),
                classification: security_core::classification::DataClassification::Internal,
            },
        );
        event.labels.insert(
            "resource_tenant".to_string(),
            crate::event::EventValue::Classified {
                value: resource_tenant.to_string(),
                classification: security_core::classification::DataClassification::Internal,
            },
        );
        event
    }
}
