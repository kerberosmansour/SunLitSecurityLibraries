//! BDD — Deny by default
use secure_authz::{
    action::Action,
    decision::{Decision, DenyReason},
    enforcer::{Authorizer, DefaultAuthorizer},
    policy::DefaultPolicyEngine,
    resource::ResourceRef,
    testkit::{test_subject, test_subject_with_tenant},
};
use std::sync::Arc;

async fn empty_authorizer() -> DefaultAuthorizer<DefaultPolicyEngine> {
    let engine = Arc::new(DefaultPolicyEngine::new_empty().await.unwrap());
    DefaultAuthorizer::new(engine)
}

/// Scenario: No policy matches → Deny(InsufficientRole) when subject has a role
#[tokio::test]
async fn test_no_policy_matches_deny_with_role() {
    let authorizer = empty_authorizer().await;
    let subject = test_subject("alice", &["viewer"]);
    let resource = ResourceRef::new("article");
    let decision = authorizer
        .authorize(&subject, &Action::Read, &resource)
        .await;
    assert!(
        matches!(
            decision,
            Decision::Deny {
                reason: DenyReason::InsufficientRole
            }
        ),
        "Expected InsufficientRole, got: {decision:?}"
    );
}

/// Scenario: Empty subject → Deny(IncompleteContext)
#[tokio::test]
async fn test_empty_subject_deny() {
    let authorizer = empty_authorizer().await;
    let subject = test_subject("", &[]);
    let resource = ResourceRef::new("article");
    let decision = authorizer
        .authorize(&subject, &Action::Read, &resource)
        .await;
    assert!(
        matches!(
            decision,
            Decision::Deny {
                reason: DenyReason::IncompleteContext
            }
        ),
        "Expected IncompleteContext, got: {decision:?}"
    );
}

/// Scenario: Missing resource kind → Deny(MissingResource)
#[tokio::test]
async fn test_missing_resource_kind_deny() {
    let authorizer = empty_authorizer().await;
    let subject = test_subject("alice", &[]);
    let resource = ResourceRef::new("");
    let decision = authorizer
        .authorize(&subject, &Action::Read, &resource)
        .await;
    assert!(
        matches!(
            decision,
            Decision::Deny {
                reason: DenyReason::MissingResource
            }
        ),
        "Expected MissingResource, got: {decision:?}"
    );
}

/// Scenario: No roles and no policy → Deny(NoPolicyMatch)
#[tokio::test]
async fn test_no_roles_no_policy_deny() {
    let authorizer = empty_authorizer().await;
    let subject = test_subject("alice", &[]);
    let resource = ResourceRef::new("article");
    let decision = authorizer
        .authorize(&subject, &Action::Read, &resource)
        .await;
    assert!(
        matches!(
            decision,
            Decision::Deny {
                reason: DenyReason::NoPolicyMatch
            }
        ),
        "Expected NoPolicyMatch, got: {decision:?}"
    );
}

/// Scenario: Cross-tenant access → always Deny(TenantMismatch)
#[tokio::test]
async fn test_cross_tenant_always_deny() {
    let authorizer = empty_authorizer().await;
    let subject = test_subject_with_tenant("alice", "tenant-A", &["admin"]);
    let resource = ResourceRef::new("article").with_tenant("tenant-B");
    let decision = authorizer
        .authorize(&subject, &Action::Admin, &resource)
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
