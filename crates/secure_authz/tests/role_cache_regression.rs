//! Runtime regressions for issue 55: roles must bind authorization cache entries.
use secure_authz::{
    action::Action,
    cache::{CacheKey, DecisionCache},
    decision::{Decision, DenyReason},
    enforcer::{Authorizer, DefaultAuthorizer},
    policy::DefaultPolicyEngine,
    resource::ResourceRef,
    testkit::test_subject,
};
use std::{sync::Arc, time::Duration};

async fn authorizer() -> DefaultAuthorizer<DefaultPolicyEngine> {
    let engine = DefaultPolicyEngine::new_empty().await.unwrap();
    engine
        .add_policy("owner", "document", "read")
        .await
        .unwrap();
    DefaultAuthorizer::new(Arc::new(engine))
}

#[tokio::test]
async fn removed_role_cannot_reuse_cached_allow() {
    let authorizer = authorizer().await;
    let resource = ResourceRef::new("document").with_id("42");
    assert!(authorizer
        .authorize(&test_subject("alice", &["owner"]), &Action::Read, &resource)
        .await
        .is_allow());
    assert!(authorizer
        .authorize(&test_subject("alice", &["child"]), &Action::Read, &resource)
        .await
        .is_deny());
    assert!(authorizer
        .authorize(&test_subject("alice", &[]), &Action::Read, &resource)
        .await
        .is_deny());
}

#[tokio::test]
async fn granted_role_cannot_reuse_cached_deny() {
    let authorizer = authorizer().await;
    let resource = ResourceRef::new("document").with_id("42");
    assert!(authorizer
        .authorize(&test_subject("alice", &["child"]), &Action::Read, &resource)
        .await
        .is_deny());
    assert!(authorizer
        .authorize(&test_subject("alice", &["owner"]), &Action::Read, &resource)
        .await
        .is_allow());
}

#[tokio::test]
async fn legacy_cache_entry_cannot_seed_authorizer_allow() {
    let engine = Arc::new(DefaultPolicyEngine::new_empty().await.unwrap());
    let cache = Arc::new(DecisionCache::new(2, Duration::from_secs(60)));
    let subject = test_subject("alice", &["child"]);
    let resource = ResourceRef::new("document").with_id("42");
    cache.insert(
        CacheKey::for_request(&subject, &Action::Read, &resource, 1),
        Decision::Allow {
            obligations: vec![],
        },
    );
    let authorizer = DefaultAuthorizer::with_cache(engine, cache);
    assert!(authorizer
        .authorize(&subject, &Action::Read, &resource)
        .await
        .is_deny());
}

#[tokio::test]
async fn invalid_subject_is_denied_after_warming_cache() {
    let authorizer = authorizer().await;
    let resource = ResourceRef::new("document");
    assert!(authorizer
        .authorize(&test_subject("alice", &["owner"]), &Action::Read, &resource)
        .await
        .is_allow());
    assert_eq!(
        authorizer
            .authorize(&test_subject("", &["owner"]), &Action::Read, &resource)
            .await,
        Decision::Deny {
            reason: DenyReason::IncompleteContext
        }
    );
}

#[tokio::test]
async fn changing_role_list_boundaries_cannot_collide() {
    let engine = Arc::new(DefaultPolicyEngine::new_empty().await.unwrap());
    engine.add_policy("a,b", "document", "read").await.unwrap();
    let authorizer = DefaultAuthorizer::new(engine);
    let resource = ResourceRef::new("document");
    assert!(authorizer
        .authorize(
            &test_subject("alice", &["a,b", "c"]),
            &Action::Read,
            &resource
        )
        .await
        .is_allow());
    assert!(authorizer
        .authorize(
            &test_subject("alice", &["a", "b,c"]),
            &Action::Read,
            &resource
        )
        .await
        .is_deny());
}
