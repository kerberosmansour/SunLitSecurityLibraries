//! BDD tests for M15: Obligation enforcement in AuthzLayer middleware.

#![cfg(feature = "axum")]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::body::Body;
use axum::routing::get;
use axum::Router;
use http::{Request, StatusCode};
use secure_authz::action::Action;
use secure_authz::decision::{Decision, DenyReason};
use secure_authz::enforcer::Authorizer;
use secure_authz::middleware::AuthzLayer;
use secure_authz::resource::ResourceRef;
use secure_authz::subject::Subject;
use security_core::identity::AuthenticatedIdentity;
use security_core::types::ActorId;
use time::OffsetDateTime;
use tower::ServiceExt;
use uuid::Uuid;

// --- Stub authorizer that returns a configurable Decision ---

#[derive(Clone)]
struct StubAuthorizer {
    decision: Decision,
}

impl Authorizer for StubAuthorizer {
    fn authorize<'a>(
        &'a self,
        _subject: &'a Subject,
        _action: &'a Action,
        _resource: &'a ResourceRef,
    ) -> Pin<Box<dyn Future<Output = Decision> + Send + 'a>> {
        let d = self.decision.clone();
        Box::pin(async move { d })
    }
}

fn test_identity() -> AuthenticatedIdentity {
    AuthenticatedIdentity {
        actor_id: ActorId::from(Uuid::new_v4()),
        tenant_id: None,
        roles: vec!["user".to_string()],
        attributes: Default::default(),
        authenticated_at: OffsetDateTime::now_utc(),
    }
}

async fn ok_handler() -> &'static str {
    "OK"
}

async fn send_request(
    app: Router,
    identity: Option<AuthenticatedIdentity>,
) -> http::Response<Body> {
    let mut req = Request::builder().uri("/test").body(Body::empty()).unwrap();
    if let Some(id) = identity {
        req.extensions_mut().insert(id);
    }
    app.oneshot(req).await.unwrap()
}

// ---------- Feature: Obligation enforcement ----------

#[tokio::test]
async fn decision_with_no_obligations_passes() {
    // Given: Decision::Allow with no obligations
    let authorizer = StubAuthorizer {
        decision: Decision::Allow {
            obligations: vec![],
        },
    };
    let app = Router::new()
        .route("/test", get(ok_handler))
        .layer(AuthzLayer::new(
            Arc::new(authorizer),
            Action::Read,
            ResourceRef::new("article"),
        ));

    // When: request with identity
    let resp = send_request(app, Some(test_identity())).await;

    // Then: request proceeds
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn decision_with_unmet_obligation_blocked() {
    // Given: Decision::Allow with obligation "require_mfa" but no MFA context
    let authorizer = StubAuthorizer {
        decision: Decision::Allow {
            obligations: vec!["require_mfa".to_string()],
        },
    };
    let app = Router::new()
        .route("/test", get(ok_handler))
        .layer(AuthzLayer::new(
            Arc::new(authorizer),
            Action::Read,
            ResourceRef::new("article"),
        ));

    // When: request with identity (no MFA context in extensions)
    let resp = send_request(app, Some(test_identity())).await;

    // Then: 403 returned
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn deny_decision_still_returns_403() {
    // Given: Decision::Deny
    let authorizer = StubAuthorizer {
        decision: Decision::Deny {
            reason: DenyReason::InsufficientRole,
        },
    };
    let app = Router::new()
        .route("/test", get(ok_handler))
        .layer(AuthzLayer::new(
            Arc::new(authorizer),
            Action::Read,
            ResourceRef::new("article"),
        ));

    // When: request with identity
    let resp = send_request(app, Some(test_identity())).await;

    // Then: 403
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
