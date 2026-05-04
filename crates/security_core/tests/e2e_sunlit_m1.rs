//! E2E runtime validation — Milestone 1 (security_core).

use security_core::{
    classification::DataClassification,
    context::{CorrelationContext, SecretRef},
    identity::{AuthenticatedIdentity, IdentityResolutionError, IdentitySource},
    time::{MockTimeSource, SystemTimeSource, TimeSource},
    types::{ActorId, RequestId, ResourceId, TenantId, TraceId},
};
use std::collections::HashMap;
use time::macros::datetime;
use uuid::Uuid;

#[test]
fn test_all_id_types_constructible() {
    let uuid = Uuid::new_v4();
    let actor = ActorId::from(uuid);
    let tenant = TenantId::from(uuid);
    let request = RequestId::from(uuid);
    let trace = TraceId::from(uuid);
    let resource = ResourceId::from(uuid);

    // Clone works
    let _ = actor.clone();
    let _ = tenant.clone();
    let _ = request.clone();
    let _ = trace.clone();
    let _ = resource.clone();

    // Values preserved via as_inner()
    assert_eq!(actor.as_inner(), &uuid);
    assert_eq!(tenant.as_inner(), &uuid);
}

#[test]
fn test_classification_ordering_at_runtime() {
    let order = [
        DataClassification::Public,
        DataClassification::Internal,
        DataClassification::Confidential,
        DataClassification::PII,
        DataClassification::Regulated,
        DataClassification::Secret,
        DataClassification::Credentials,
    ];
    for i in 0..order.len() - 1 {
        assert!(
            order[i] < order[i + 1],
            "Expected {:?} < {:?}",
            order[i],
            order[i + 1]
        );
    }
}

#[test]
fn test_correlation_context_propagation() {
    let req_id = RequestId::generate();
    let actor_id = ActorId::from(Uuid::new_v4());
    let trace_id = TraceId::from(Uuid::new_v4());

    let ctx = CorrelationContext::new(req_id.clone())
        .with_actor(actor_id.clone())
        .with_trace(trace_id.clone());

    // Clone works
    let ctx2 = ctx.clone();

    assert_eq!(ctx2.request_id(), &req_id);
    assert_eq!(ctx2.actor_id(), Some(&actor_id));
    assert_eq!(ctx2.trace_id(), Some(&trace_id));
}

#[test]
fn test_secret_ref_does_not_leak() {
    let sr = SecretRef::new("vault://kv/super-secret".to_string());
    let debug_output = format!("{:?}", sr);
    assert!(
        !debug_output.contains("vault://kv/super-secret"),
        "SecretRef must not leak its value in debug output"
    );
    assert!(!debug_output.contains("super-secret"));
}

#[test]
fn test_workspace_compiles() {
    // If we're running this test, the workspace compiled successfully.
    let _compiled = true;
}

#[test]
fn test_time_sources_constructible() {
    let _sys = SystemTimeSource;
    let fixed = datetime!(2025-06-01 12:00:00 UTC);
    let mock = MockTimeSource::new(fixed);
    assert_eq!(mock.now(), fixed);
}

struct TestIdentitySource {
    actor_id: ActorId,
}

impl IdentitySource for TestIdentitySource {
    async fn resolve(
        &self,
        _token: &str,
    ) -> Result<AuthenticatedIdentity, IdentityResolutionError> {
        Ok(AuthenticatedIdentity {
            actor_id: self.actor_id.clone(),
            tenant_id: None,
            roles: vec!["TEST_ROLE".to_string()],
            attributes: HashMap::new(),
            authenticated_at: time::OffsetDateTime::now_utc(),
        })
    }
}

#[tokio::test]
async fn test_identity_source_implementable() {
    let uuid = Uuid::new_v4();
    let source = TestIdentitySource {
        actor_id: ActorId::from(uuid),
    };
    let identity = source.resolve("some-token").await.unwrap();
    assert_eq!(identity.actor_id.as_inner(), &uuid);
    assert_eq!(identity.roles, vec!["TEST_ROLE".to_string()]);
}
