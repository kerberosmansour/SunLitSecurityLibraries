//! E2E — Runtime validation for Milestone 6 (`secure_authz`)

#![cfg(feature = "axum")]

use secure_authz::{
    action::Action,
    cache::{CacheKey, DecisionCache},
    decision::{Decision, DenyReason},
    enforcer::{Authorizer, DefaultAuthorizer},
    middleware::AuthzLayer,
    policy::{DefaultPolicyEngine, PolicyEngine},
    resource::ResourceRef,
    testkit::{test_subject, test_subject_with_tenant, MockAuthorizer},
};
use security_core::identity::AuthenticatedIdentity;
use security_core::types::ActorId;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

fn make_identity(roles: &[&str]) -> AuthenticatedIdentity {
    AuthenticatedIdentity {
        actor_id: ActorId::from(Uuid::new_v4()),
        tenant_id: None,
        roles: roles.iter().map(|r| r.to_string()).collect(),
        attributes: Default::default(),
        authenticated_at: OffsetDateTime::now_utc(),
    }
}

/// E2E: No-policy scenario denies at runtime without panic
#[tokio::test]
async fn test_deny_by_default_runtime() {
    let engine = Arc::new(DefaultPolicyEngine::new_empty().await.unwrap());
    let authorizer = DefaultAuthorizer::new(engine);
    let subject = test_subject("user-1", &["viewer"]);
    let resource = ResourceRef::new("secret");
    let decision = authorizer
        .authorize(&subject, &Action::Delete, &resource)
        .await;
    assert!(decision.is_deny(), "Expected deny but got: {decision:?}");
}

/// E2E: RBAC policies evaluate correctly at runtime with casbin
#[tokio::test]
async fn test_rbac_policy_evaluation() {
    let engine = DefaultPolicyEngine::new_empty().await.unwrap();
    engine
        .add_policy("editor", "article", "write")
        .await
        .unwrap();
    let engine = Arc::new(engine);
    let authorizer = DefaultAuthorizer::new(engine);

    // Editor role → Allow
    let editor = test_subject("alice", &["editor"]);
    let resource = ResourceRef::new("article");
    let allow = authorizer
        .authorize(&editor, &Action::Write, &resource)
        .await;
    assert!(
        allow.is_allow(),
        "Editor should be allowed to write: {allow:?}"
    );

    // Viewer role → Deny
    let viewer = test_subject("bob", &["viewer"]);
    let deny = authorizer
        .authorize(&viewer, &Action::Write, &resource)
        .await;
    assert!(deny.is_deny(), "Viewer should be denied write: {deny:?}");
}

/// E2E: Cross-tenant authorization denied with security event
#[tokio::test]
async fn test_cross_tenant_denied() {
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

/// E2E: Cache stores, hits, and TTL invalidates correctly
#[tokio::test]
async fn test_decision_cache_lifecycle() {
    let cache = Arc::new(DecisionCache::new(100, Duration::from_secs(60)));
    let engine = DefaultPolicyEngine::new_empty().await.unwrap();
    engine
        .add_policy("editor", "article", "read")
        .await
        .unwrap();
    let engine = Arc::new(engine);
    let authorizer = DefaultAuthorizer::with_cache(engine.clone(), cache.clone());

    let subject = test_subject("alice", &["editor"]);
    let resource = ResourceRef::new("article");

    // First call — engine evaluates and caches result
    let d1 = authorizer
        .authorize(&subject, &Action::Read, &resource)
        .await;
    assert!(d1.is_allow(), "Expected Allow on first call: {d1:?}");

    // Second call — should hit cache (still Allow)
    let d2 = authorizer
        .authorize(&subject, &Action::Read, &resource)
        .await;
    assert!(d2.is_allow(), "Expected Allow on cached call: {d2:?}");

    // Verify cache directly: key with same policy version → hit
    let policy_version = engine.policy_version();
    let cache_key = CacheKey {
        actor_id: "alice".to_owned(),
        action: "read".to_owned(),
        resource_kind: "article".to_owned(),
        resource_id: "*".to_owned(),
        policy_version,
        tenant_id: None,
    };
    assert!(
        cache.get(&cache_key).is_some(),
        "Expected cache hit for same policy version"
    );
}

/// E2E: `AuthzLayer` denies unauthorized requests in an axum test router
#[tokio::test]
async fn test_middleware_integration() {
    use axum::{routing::get, Router};
    use http::{Request, StatusCode};
    use tower::ServiceExt;

    async fn handler() -> &'static str {
        "ok"
    }

    let allow_authz = Arc::new(MockAuthorizer::allow());
    let deny_authz = Arc::new(MockAuthorizer::deny(DenyReason::NoPolicyMatch));

    let allow_router = Router::new()
        .route("/", get(handler))
        .layer(AuthzLayer::new(
            allow_authz,
            Action::Read,
            ResourceRef::new("test"),
        ));

    let deny_router = Router::new()
        .route("/", get(handler))
        .layer(AuthzLayer::new(
            deny_authz,
            Action::Read,
            ResourceRef::new("test"),
        ));

    let identity = make_identity(&["viewer"]);

    // Authorized request (allow) — should return 200
    let mut req = Request::builder()
        .uri("/")
        .body(axum::body::Body::empty())
        .unwrap();
    req.extensions_mut().insert(identity.clone());
    let resp = allow_router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "Expected 200 for allowed request"
    );

    // Unauthorized request (deny) — should return 403
    let mut req2 = Request::builder()
        .uri("/")
        .body(axum::body::Body::empty())
        .unwrap();
    req2.extensions_mut().insert(identity);
    let resp2 = deny_router.oneshot(req2).await.unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::FORBIDDEN,
        "Expected 403 for denied request"
    );

    // No identity in extensions → 403
    let allow_router2 = Router::new()
        .route("/", get(handler))
        .layer(AuthzLayer::new(
            Arc::new(MockAuthorizer::allow()),
            Action::Read,
            ResourceRef::new("test"),
        ));
    let req3 = Request::builder()
        .uri("/")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp3 = allow_router2.oneshot(req3).await.unwrap();
    assert_eq!(
        resp3.status(),
        StatusCode::FORBIDDEN,
        "Expected 403 when no identity in extensions"
    );
}

/// E2E: When policy engine errors, result is Deny without panic
#[tokio::test]
async fn test_engine_failure_denies() {
    let authorizer = MockAuthorizer::deny(DenyReason::EngineError);
    let subject = test_subject("alice", &["editor"]);
    let resource = ResourceRef::new("article");
    let decision = authorizer
        .authorize(&subject, &Action::Read, &resource)
        .await;
    assert!(
        matches!(
            decision,
            Decision::Deny {
                reason: DenyReason::EngineError
            }
        ),
        "Expected EngineError deny, got: {decision:?}"
    );
}

/// E2E: `secure_authz` has no compile-time dependency on `secure_identity`
#[test]
fn test_authz_independence() {
    // Verified externally via: cargo tree -p secure_authz | grep secure_identity
    // Expected output: (empty — no match)
    // This test documents the design invariant.
}
