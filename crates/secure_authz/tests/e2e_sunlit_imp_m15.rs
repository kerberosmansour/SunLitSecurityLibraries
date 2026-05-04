//! E2E — Runtime validation for Milestone 15 (`secure_authz` cache fix + obligation enforcement).

#![cfg(feature = "axum")]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use secure_authz::action::Action;
use secure_authz::cache::{CacheKey, DecisionCache};
use secure_authz::decision::Decision;
use secure_authz::enforcer::{Authorizer, DefaultAuthorizer};
use secure_authz::policy::DefaultPolicyEngine;
use secure_authz::resource::ResourceRef;
use secure_authz::testkit::test_subject_with_tenant;

/// E2E: Tenant-scoped cache prevents cross-tenant cache poisoning at runtime.
#[tokio::test]
async fn test_tenant_scoped_cache_prevents_cross_tenant_poisoning() {
    // Given: a policy allowing editors to read articles
    let engine = DefaultPolicyEngine::new_empty().await.unwrap();
    engine
        .add_policy("editor", "article", "read")
        .await
        .unwrap();
    let cache = Arc::new(DecisionCache::new(100, Duration::from_secs(60)));
    let authorizer = DefaultAuthorizer::with_cache(Arc::new(engine), cache.clone());

    // Actor in tenant-A gets allowed (populates cache)
    let subject_a = test_subject_with_tenant("alice", "tenant-A", &["editor"]);
    let resource_a = ResourceRef::new("article").with_tenant("tenant-A");
    let decision_a = authorizer
        .authorize(&subject_a, &Action::Read, &resource_a)
        .await;
    assert!(
        decision_a.is_allow(),
        "Tenant-A editor should be allowed: {decision_a:?}"
    );

    // Same actor, same resource kind, but different tenant should NOT get the cached result
    // (cross-tenant is blocked before cache, but cache key must also be tenant-scoped)
    let subject_b = test_subject_with_tenant("alice", "tenant-B", &["editor"]);
    let resource_b = ResourceRef::new("article").with_tenant("tenant-B");
    let decision_b = authorizer
        .authorize(&subject_b, &Action::Read, &resource_b)
        .await;
    // This should also allow (same policy), but via separate cache entry
    assert!(
        decision_b.is_allow(),
        "Tenant-B editor should be allowed: {decision_b:?}"
    );

    // Verify cache has two separate entries by checking with constructed keys
    // After add_policy, version is 2 (starts at 1 + 1 increment)
    let key_a = CacheKey {
        actor_id: "alice".into(),
        action: "read".into(),
        resource_kind: "article".into(),
        resource_id: "*".into(),
        policy_version: 2,
        tenant_id: Some("tenant-A".into()),
    };
    let key_b = CacheKey {
        actor_id: "alice".into(),
        action: "read".into(),
        resource_kind: "article".into(),
        resource_id: "*".into(),
        policy_version: 2,
        tenant_id: Some("tenant-B".into()),
    };
    assert!(
        cache.get(&key_a).is_some(),
        "Tenant-A cache entry should exist"
    );
    assert!(
        cache.get(&key_b).is_some(),
        "Tenant-B cache entry should exist"
    );
}

/// E2E: Obligation enforcement blocks requests with unsatisfied obligations.
#[tokio::test]
async fn test_obligation_enforcement_blocks_unmet_obligations() {
    use axum::body::Body;
    use axum::routing::get;
    use axum::Router;
    use http::{Request, StatusCode};
    use secure_authz::middleware::AuthzLayer;
    use security_core::identity::AuthenticatedIdentity;
    use security_core::types::ActorId;
    use time::OffsetDateTime;
    use tower::ServiceExt;
    use uuid::Uuid;

    // Stub authorizer that returns Allow with obligations
    #[derive(Clone)]
    struct ObligationAuthorizer;

    impl Authorizer for ObligationAuthorizer {
        fn authorize<'a>(
            &'a self,
            _subject: &'a secure_authz::subject::Subject,
            _action: &'a Action,
            _resource: &'a ResourceRef,
        ) -> Pin<Box<dyn Future<Output = Decision> + Send + 'a>> {
            Box::pin(async {
                Decision::Allow {
                    obligations: vec!["require_mfa".to_string()],
                }
            })
        }
    }

    let app = Router::new()
        .route("/protected", get(|| async { "secret" }))
        .layer(AuthzLayer::new(
            Arc::new(ObligationAuthorizer),
            Action::Read,
            ResourceRef::new("secret"),
        ));

    let identity = AuthenticatedIdentity {
        actor_id: ActorId::from(Uuid::new_v4()),
        tenant_id: None,
        roles: vec!["user".to_string()],
        attributes: Default::default(),
        authenticated_at: OffsetDateTime::now_utc(),
    };

    let mut req = Request::builder()
        .uri("/protected")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(identity);

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "Request with unmet obligations should be blocked"
    );
}
