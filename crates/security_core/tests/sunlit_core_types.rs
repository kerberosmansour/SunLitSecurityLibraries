//! BDD acceptance tests for security_core types — Milestone 1.

use security_core::{
    classification::DataClassification,
    context::{CorrelationContext, ReasonCode, SecretRef},
    identity::{AuthenticatedIdentity, IdentityResolutionError, IdentitySource},
    redact::RedactedDisplay,
    time::{MockTimeSource, SystemTimeSource, TimeSource},
    types::{ActorId, RequestId, TenantId},
};
use time::macros::datetime;
use uuid::Uuid;

// --- Feature: Shared ID types ---

#[test]
fn actor_id_display_is_uuid_string() {
    let uuid = Uuid::new_v4();
    let actor = ActorId::from(uuid);
    assert_eq!(actor.to_string(), uuid.to_string());
}

#[test]
fn tenant_id_display_is_uuid_string() {
    let uuid = Uuid::new_v4();
    let tenant = TenantId::from(uuid);
    assert_eq!(tenant.to_string(), uuid.to_string());
}

#[test]
fn secret_ref_debug_does_not_leak() {
    let sr = SecretRef::new("vault://kv/db-pass".to_string());
    let debug_output = format!("{:?}", sr);
    assert_eq!(debug_output, "SecretRef(REDACTED)");
    assert!(!debug_output.contains("vault://kv/db-pass"));
}

#[test]
fn request_id_generates_unique() {
    let r1 = RequestId::generate();
    let r2 = RequestId::generate();
    assert_ne!(r1, r2);
}

// --- Feature: Data classification ordering ---

#[test]
fn classification_public_less_than_secret() {
    assert!(DataClassification::Public < DataClassification::Secret);
}

#[test]
fn all_variants_sorted_correctly() {
    let mut variants = vec![
        DataClassification::Credentials,
        DataClassification::Secret,
        DataClassification::Regulated,
        DataClassification::PII,
        DataClassification::Confidential,
        DataClassification::Internal,
        DataClassification::Public,
    ];
    variants.sort();
    assert_eq!(
        variants,
        vec![
            DataClassification::Public,
            DataClassification::Internal,
            DataClassification::Confidential,
            DataClassification::PII,
            DataClassification::Regulated,
            DataClassification::Secret,
            DataClassification::Credentials,
        ]
    );
}

// --- Feature: Correlation context ---

#[test]
fn correlation_context_construction() {
    let req_id = RequestId::generate();
    let actor_id = ActorId::from(Uuid::new_v4());
    let ctx = CorrelationContext::new(req_id.clone()).with_actor(actor_id.clone());
    assert_eq!(ctx.request_id(), &req_id);
    assert_eq!(ctx.actor_id(), Some(&actor_id));
}

#[test]
fn correlation_context_optional_actor_is_none() {
    let req_id = RequestId::generate();
    let ctx = CorrelationContext::new(req_id);
    assert_eq!(ctx.actor_id(), None);
}

// --- Feature: TimeSource ---

#[test]
fn system_time_source_returns_current_time() {
    let ts = SystemTimeSource;
    let now = ts.now();
    let real_now = time::OffsetDateTime::now_utc();
    let diff = (real_now - now).abs();
    assert!(diff.whole_seconds() < 2, "Time should be within 2 seconds");
}

#[test]
fn mock_time_source_returns_fixed_time() {
    let fixed = datetime!(2025-01-01 00:00:00 UTC);
    let ts = MockTimeSource::new(fixed);
    assert_eq!(ts.now(), fixed);
}

// --- Feature: Redact trait ---

#[test]
fn redacted_display_masks_value() {
    let rd = RedactedDisplay::new("secret123");
    assert_eq!(rd.to_string(), "[REDACTED]");
}

// --- Feature: IdentitySource trait ---

struct MockIdentitySource;

impl IdentitySource for MockIdentitySource {
    async fn resolve(
        &self,
        _token: &str,
    ) -> Result<AuthenticatedIdentity, IdentityResolutionError> {
        use std::collections::HashMap;
        Ok(AuthenticatedIdentity {
            actor_id: ActorId::from(Uuid::new_v4()),
            tenant_id: None,
            roles: vec!["ADMIN".to_string()],
            attributes: HashMap::new(),
            authenticated_at: time::OffsetDateTime::now_utc(),
        })
    }
}

#[tokio::test]
async fn identity_source_is_open_trait() {
    let source = MockIdentitySource;
    let result = source.resolve("test-token").await;
    assert!(result.is_ok());
}

#[test]
fn authenticated_identity_carries_actor_and_tenant() {
    use std::collections::HashMap;
    let actor_id = ActorId::from(Uuid::new_v4());
    let tenant_id = TenantId::from(Uuid::new_v4());
    let identity = AuthenticatedIdentity {
        actor_id: actor_id.clone(),
        tenant_id: Some(tenant_id.clone()),
        roles: vec!["READER".to_string()],
        attributes: HashMap::new(),
        authenticated_at: time::OffsetDateTime::now_utc(),
    };
    assert_eq!(identity.actor_id, actor_id);
    assert_eq!(identity.tenant_id, Some(tenant_id));
    assert_eq!(identity.roles, vec!["READER".to_string()]);
}

#[test]
fn authenticated_identity_optional_tenant_is_none() {
    use std::collections::HashMap;
    let identity = AuthenticatedIdentity {
        actor_id: ActorId::from(Uuid::new_v4()),
        tenant_id: None,
        roles: vec![],
        attributes: HashMap::new(),
        authenticated_at: time::OffsetDateTime::now_utc(),
    };
    assert_eq!(identity.tenant_id, None);
}

#[test]
fn authenticated_identity_roles_are_typed() {
    use std::collections::HashMap;
    let identity = AuthenticatedIdentity {
        actor_id: ActorId::from(Uuid::new_v4()),
        tenant_id: None,
        roles: vec!["ADMIN".to_string(), "READER".to_string()],
        attributes: HashMap::new(),
        authenticated_at: time::OffsetDateTime::now_utc(),
    };
    assert_eq!(
        identity.roles,
        vec!["ADMIN".to_string(), "READER".to_string()]
    );
}

// Silence unused import warnings for ReasonCode (imported for completeness)
#[test]
fn reason_code_display() {
    let rc = ReasonCode::new("POLICY_VIOLATION");
    assert_eq!(rc.to_string(), "POLICY_VIOLATION");
}
