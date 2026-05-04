//! Decision event emission to `security_events`.
use security_core::severity::SecuritySeverity;
use security_core::types::TenantId;
use security_events::emit::emit_security_event;
use security_events::event::{EventOutcome, SecurityEvent};
use security_events::kind::EventKind;
use std::collections::BTreeMap;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::action::Action;
use crate::decision::{Decision, DenyReason};
use crate::resource::ResourceRef;
use crate::subject::Subject;

/// Emits a structured security event for the given authorization decision.
///
/// Deny decisions always emit an event. Allow decisions are not logged at high severity.
pub fn log_decision(
    subject: &Subject,
    _action: &Action,
    resource: &ResourceRef,
    decision: &Decision,
) {
    if let Decision::Deny { reason } = decision {
        let (kind, severity) = match reason {
            DenyReason::TenantMismatch => (EventKind::CrossTenantAttempt, SecuritySeverity::High),
            DenyReason::EngineError => (EventKind::ErrorEscalation, SecuritySeverity::Critical),
            _ => (EventKind::AuthzDeny, SecuritySeverity::Medium),
        };
        let tenant = subject
            .tenant_id
            .as_deref()
            .and_then(|t| t.parse::<Uuid>().ok())
            .map(TenantId::from);
        let event = SecurityEvent {
            timestamp: OffsetDateTime::now_utc(),
            event_id: Uuid::new_v4(),
            parent_event_id: None,
            kind,
            severity,
            outcome: EventOutcome::Blocked,
            actor: Some(subject.actor_id.clone()),
            tenant,
            source_ip: None,
            request_id: None,
            trace_id: None,
            session_id: None,
            resource: Some(format!(
                "{}/{}",
                resource.kind,
                resource.resource_id.as_deref().unwrap_or("*")
            )),
            reason_code: Some(deny_reason_code(reason)),
            hmac: None,
            labels: BTreeMap::new(),
        };
        emit_security_event(event);
    }
}

fn deny_reason_code(reason: &DenyReason) -> &'static str {
    match reason {
        DenyReason::NoPolicyMatch => "NO_POLICY_MATCH",
        DenyReason::InsufficientRole => "INSUFFICIENT_ROLE",
        DenyReason::TenantMismatch => "TENANT_MISMATCH",
        DenyReason::IncompleteContext => "INCOMPLETE_CONTEXT",
        DenyReason::EngineError => "ENGINE_ERROR",
        DenyReason::OwnershipRequired => "OWNERSHIP_REQUIRED",
        DenyReason::MissingResource => "MISSING_RESOURCE",
        DenyReason::AttributeMismatch => "ATTRIBUTE_MISMATCH",
        DenyReason::PermissionExpired => "PERMISSION_EXPIRED",
        DenyReason::PermissionNotYetActive => "PERMISSION_NOT_YET_ACTIVE",
        DenyReason::DeviceTrustRequired => "DEVICE_TRUST_REQUIRED",
        DenyReason::DeviceTrustTierTooLow => "DEVICE_TRUST_TIER_TOO_LOW",
        DenyReason::DeviceTrustRevoked => "DEVICE_TRUST_REVOKED",
        DenyReason::UntrustedDeviceMetadata => "UNTRUSTED_DEVICE_METADATA",
        DenyReason::DeviceSessionBindingMismatch => "DEVICE_SESSION_BINDING_MISMATCH",
        DenyReason::TestTrustProfileRequired => "TEST_TRUST_PROFILE_REQUIRED",
    }
}
