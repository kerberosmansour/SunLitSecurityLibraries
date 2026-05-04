//! BDD — Tenant isolation
use secure_authz::{
    action::Action,
    decision::{Decision, DenyReason},
    enforcer::{Authorizer, DefaultAuthorizer},
    policy::DefaultPolicyEngine,
    resource::ResourceRef,
    testkit::{test_subject, test_subject_with_tenant},
};
use std::sync::Arc;

/// Scenario: Same-tenant access — allowed when policy permits
#[tokio::test]
async fn test_same_tenant_access_allowed() {
    let engine = DefaultPolicyEngine::new_empty().await.unwrap();
    engine
        .add_policy("editor", "article", "read")
        .await
        .unwrap();
    let authorizer = DefaultAuthorizer::new(Arc::new(engine));
    let subject = test_subject_with_tenant("alice", "tenant-A", &["editor"]);
    let resource = ResourceRef::new("article").with_tenant("tenant-A");
    let decision = authorizer
        .authorize(&subject, &Action::Read, &resource)
        .await;
    assert!(
        matches!(decision, Decision::Allow { .. }),
        "Expected Allow for same-tenant access, got: {decision:?}"
    );
}

/// Scenario: Cross-tenant blocked — Deny(TenantMismatch)
#[tokio::test]
async fn test_cross_tenant_blocked() {
    let engine = DefaultPolicyEngine::new_empty().await.unwrap();
    engine
        .add_policy("editor", "article", "read")
        .await
        .unwrap();
    let authorizer = DefaultAuthorizer::new(Arc::new(engine));
    let subject = test_subject_with_tenant("alice", "tenant-A", &["editor"]);
    let resource = ResourceRef::new("article").with_tenant("tenant-B");
    let decision = authorizer
        .authorize(&subject, &Action::Read, &resource)
        .await;
    assert!(
        matches!(
            decision,
            Decision::Deny {
                reason: DenyReason::TenantMismatch
            }
        ),
        "Expected TenantMismatch, got: {decision:?}"
    );
}

/// Scenario: Subject with no tenant accessing tenanted resource → Deny
#[tokio::test]
async fn test_no_tenant_subject_denied_for_tenanted_resource() {
    let engine = DefaultPolicyEngine::new_empty().await.unwrap();
    engine
        .add_policy("editor", "article", "read")
        .await
        .unwrap();
    let authorizer = DefaultAuthorizer::new(Arc::new(engine));
    let subject = test_subject("alice", &["editor"]); // no tenant
    let resource = ResourceRef::new("article").with_tenant("tenant-B");
    let decision = authorizer
        .authorize(&subject, &Action::Read, &resource)
        .await;
    assert!(
        decision.is_deny(),
        "Expected Deny for subject without tenant accessing tenanted resource, got: {decision:?}"
    );
}

/// Scenario: Resource without tenant is accessible regardless of subject tenant
#[tokio::test]
async fn test_resource_without_tenant_accessible() {
    let engine = DefaultPolicyEngine::new_empty().await.unwrap();
    engine
        .add_policy("editor", "article", "read")
        .await
        .unwrap();
    let authorizer = DefaultAuthorizer::new(Arc::new(engine));
    let subject = test_subject_with_tenant("alice", "tenant-A", &["editor"]);
    let resource = ResourceRef::new("article"); // no tenant on resource
    let decision = authorizer
        .authorize(&subject, &Action::Read, &resource)
        .await;
    assert!(
        matches!(decision, Decision::Allow { .. }),
        "Expected Allow for tenant-free resource, got: {decision:?}"
    );
}
