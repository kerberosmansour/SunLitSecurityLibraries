//! BDD: cross-framework parity for `AuthzLayer` (axum) vs `AuthzTransform`
//! (actix-web) — sg-gate-a M2. Both paths must return identical status codes
//! on identical inputs.

#![cfg(all(feature = "axum", feature = "actix-web"))]

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use actix_web::{test as atest, web as aweb, App as AApp, HttpResponse as AResp};
use axum::body::Body;
use axum::extract::Request;
use axum::routing::get;
use axum::Router;
use secure_authz::action::Action;
use secure_authz::actix::AuthzTransform;
use secure_authz::decision::{Decision, DenyReason};
use secure_authz::enforcer::Authorizer;
use secure_authz::middleware::AuthzLayer;
use secure_authz::resource::ResourceRef;
use secure_authz::subject::Subject;
use security_core::identity::AuthenticatedIdentity;
use security_core::types::{ActorId, TenantId};
use time::OffsetDateTime;
use tower::ServiceExt;
use uuid::Uuid;

#[derive(Clone)]
struct FixedAuthorizer(Decision);

impl Authorizer for FixedAuthorizer {
    fn authorize<'a>(
        &'a self,
        _subject: &'a Subject,
        _action: &'a Action,
        _resource: &'a ResourceRef,
    ) -> Pin<Box<dyn std::future::Future<Output = Decision> + Send + 'a>> {
        let d = self.0.clone();
        Box::pin(async move { d })
    }
}

fn identity() -> AuthenticatedIdentity {
    AuthenticatedIdentity {
        actor_id: ActorId::from(Uuid::new_v4()),
        tenant_id: Some(TenantId::from(Uuid::new_v4())),
        roles: vec!["reader".to_owned()],
        attributes: HashMap::new(),
        authenticated_at: OffsetDateTime::now_utc(),
    }
}

async fn axum_status(decision: Decision, inject_identity: bool) -> u16 {
    let authz = Arc::new(FixedAuthorizer(decision));
    let layer = AuthzLayer::new(authz, Action::Read, ResourceRef::new("item"));
    let id = identity();
    let app = Router::<()>::new()
        .route("/", get(|| async { "ok" }))
        .layer(layer)
        .layer(axum::middleware::from_fn(
            move |mut req: Request, next: axum::middleware::Next| {
                let id = id.clone();
                async move {
                    if inject_identity {
                        req.extensions_mut().insert(id);
                    }
                    next.run(req).await
                }
            },
        ));
    let req = Request::builder()
        .method("GET")
        .uri("/")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    resp.status().as_u16()
}

async fn actix_status(decision: Decision, inject_identity: bool) -> u16 {
    use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
    use actix_web::{Error, HttpMessage};
    use std::future::{ready, Future, Ready};

    #[derive(Clone)]
    struct InjectId(Option<AuthenticatedIdentity>);

    impl<S, B> Transform<S, ServiceRequest> for InjectId
    where
        S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
        S::Future: 'static,
        B: 'static,
    {
        type Response = ServiceResponse<B>;
        type Error = Error;
        type Transform = InjectIdMw<S>;
        type InitError = ();
        type Future = Ready<Result<Self::Transform, Self::InitError>>;
        fn new_transform(&self, service: S) -> Self::Future {
            ready(Ok(InjectIdMw {
                service,
                id: self.0.clone(),
            }))
        }
    }
    struct InjectIdMw<S> {
        service: S,
        id: Option<AuthenticatedIdentity>,
    }
    impl<S, B> Service<ServiceRequest> for InjectIdMw<S>
    where
        S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
        S::Future: 'static,
        B: 'static,
    {
        type Response = ServiceResponse<B>;
        type Error = Error;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;
        forward_ready!(service);
        fn call(&self, req: ServiceRequest) -> Self::Future {
            if let Some(id) = &self.id {
                req.extensions_mut().insert(id.clone());
            }
            Box::pin(self.service.call(req))
        }
    }

    let authz = Arc::new(FixedAuthorizer(decision));
    let id = if inject_identity {
        Some(identity())
    } else {
        None
    };
    let srv = atest::init_service(
        AApp::new()
            .wrap(AuthzTransform::new(
                authz,
                Action::Read,
                ResourceRef::new("item"),
            ))
            .wrap(InjectId(id))
            .route("/", aweb::get().to(|| async { AResp::Ok().body("ok") })),
    )
    .await;
    let resp = atest::call_service(&srv, atest::TestRequest::get().uri("/").to_request()).await;
    resp.status().as_u16()
}

#[tokio::test]
async fn parity_authz_allow_match() {
    let axum = axum_status(
        Decision::Allow {
            obligations: vec![],
        },
        true,
    )
    .await;
    let actix = actix_status(
        Decision::Allow {
            obligations: vec![],
        },
        true,
    )
    .await;
    assert_eq!(axum, actix);
    assert_eq!(axum, 200);
}

#[tokio::test]
async fn parity_authz_deny_match() {
    let axum = axum_status(
        Decision::Deny {
            reason: DenyReason::InsufficientRole,
        },
        true,
    )
    .await;
    let actix = actix_status(
        Decision::Deny {
            reason: DenyReason::InsufficientRole,
        },
        true,
    )
    .await;
    assert_eq!(axum, actix);
    assert_eq!(axum, 403);
}

#[tokio::test]
async fn parity_authz_missing_identity_match() {
    let axum = axum_status(
        Decision::Allow {
            obligations: vec![],
        },
        false,
    )
    .await;
    let actix = actix_status(
        Decision::Allow {
            obligations: vec![],
        },
        false,
    )
    .await;
    assert_eq!(axum, actix);
    assert_eq!(axum, 403);
}
