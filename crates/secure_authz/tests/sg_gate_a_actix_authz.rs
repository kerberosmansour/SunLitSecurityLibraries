//! BDD: Actix-web 4 `AuthzTransform` middleware — sg-gate-a M2.
//!
//! Validates that `secure_authz::actix::AuthzTransform` enforces
//! `Authorizer::authorize` decisions with the same semantics as the axum
//! `AuthzLayer`: allow on `Decision::Allow`, 403 on `Decision::Deny`, 403
//! when no identity is in extensions, and obligation-aware allow.

#![cfg(feature = "actix-web")]

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use actix_web::{http::StatusCode, test, web, App, HttpResponse};
use secure_authz::action::Action;
use secure_authz::actix::AuthzTransform;
use secure_authz::decision::{Decision, DenyReason};
use secure_authz::enforcer::Authorizer;
use secure_authz::resource::ResourceRef;
use secure_authz::subject::Subject;
use security_core::identity::AuthenticatedIdentity;
use security_core::types::{ActorId, TenantId};
use time::OffsetDateTime;
use uuid::Uuid;

fn identity() -> AuthenticatedIdentity {
    AuthenticatedIdentity {
        actor_id: ActorId::from(Uuid::new_v4()),
        tenant_id: Some(TenantId::from(Uuid::new_v4())),
        roles: vec!["reader".to_owned()],
        attributes: HashMap::new(),
        authenticated_at: OffsetDateTime::now_utc(),
    }
}

/// A freely-configurable mock that always returns a fixed decision.
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

async fn inner() -> HttpResponse {
    HttpResponse::Ok().body("ok")
}

/// Actix middleware that inserts an `AuthenticatedIdentity` (and optionally
/// an `ObligationFulfillment`) into request extensions. Mimics the role a
/// real auth layer would play upstream of `AuthzTransform`.
mod fixture {
    use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
    use actix_web::{Error, HttpMessage};
    use secure_authz::enforce::ObligationFulfillment;
    use security_core::identity::AuthenticatedIdentity;
    use std::future::{ready, Future, Ready};
    use std::pin::Pin;

    #[derive(Clone, Default)]
    pub struct Context {
        pub identity: Option<AuthenticatedIdentity>,
        pub fulfilled: Option<Vec<String>>,
    }

    impl<S, B> Transform<S, ServiceRequest> for Context
    where
        S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
        S::Future: 'static,
        B: 'static,
    {
        type Response = ServiceResponse<B>;
        type Error = Error;
        type Transform = Middleware<S>;
        type InitError = ();
        type Future = Ready<Result<Self::Transform, Self::InitError>>;
        fn new_transform(&self, service: S) -> Self::Future {
            ready(Ok(Middleware {
                service,
                ctx: self.clone(),
            }))
        }
    }

    pub struct Middleware<S> {
        service: S,
        ctx: Context,
    }

    impl<S, B> Service<ServiceRequest> for Middleware<S>
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
            if let Some(id) = &self.ctx.identity {
                req.extensions_mut().insert(id.clone());
            }
            if let Some(f) = &self.ctx.fulfilled {
                req.extensions_mut().insert(ObligationFulfillment {
                    fulfilled: f.clone(),
                });
            }
            Box::pin(self.service.call(req))
        }
    }
}

#[actix_web::test]
async fn actix_authz_allow_pass_through() {
    let authz = Arc::new(FixedAuthorizer(Decision::Allow {
        obligations: vec![],
    }));
    let srv = test::init_service(
        App::new()
            .wrap(AuthzTransform::new(
                authz,
                Action::Read,
                ResourceRef::new("item"),
            ))
            .wrap(fixture::Context {
                identity: Some(identity()),
                fulfilled: None,
            })
            .route("/", web::get().to(inner)),
    )
    .await;
    let resp = test::call_service(&srv, test::TestRequest::get().uri("/").to_request()).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn actix_authz_deny_returns_403() {
    let authz = Arc::new(FixedAuthorizer(Decision::Deny {
        reason: DenyReason::InsufficientRole,
    }));
    let srv = test::init_service(
        App::new()
            .wrap(AuthzTransform::new(
                authz,
                Action::Read,
                ResourceRef::new("item"),
            ))
            .wrap(fixture::Context {
                identity: Some(identity()),
                fulfilled: None,
            })
            .route("/", web::get().to(inner)),
    )
    .await;
    let resp = test::call_service(&srv, test::TestRequest::get().uri("/").to_request()).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn actix_authz_missing_identity_returns_403() {
    let authz = Arc::new(FixedAuthorizer(Decision::Allow {
        obligations: vec![],
    }));
    let srv = test::init_service(
        App::new()
            .wrap(AuthzTransform::new(
                authz,
                Action::Read,
                ResourceRef::new("item"),
            ))
            .wrap(fixture::Context::default())
            .route("/", web::get().to(inner)),
    )
    .await;
    let resp = test::call_service(&srv, test::TestRequest::get().uri("/").to_request()).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn actix_authz_obligations_unfulfilled_returns_403() {
    let authz = Arc::new(FixedAuthorizer(Decision::Allow {
        obligations: vec!["mfa".to_owned()],
    }));
    let srv = test::init_service(
        App::new()
            .wrap(AuthzTransform::new(
                authz,
                Action::Write,
                ResourceRef::new("doc"),
            ))
            .wrap(fixture::Context {
                identity: Some(identity()),
                fulfilled: None,
            })
            .route("/", web::get().to(inner)),
    )
    .await;
    let resp = test::call_service(&srv, test::TestRequest::get().uri("/").to_request()).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn actix_authz_obligations_fulfilled_allow() {
    let authz = Arc::new(FixedAuthorizer(Decision::Allow {
        obligations: vec!["mfa".to_owned()],
    }));
    let srv = test::init_service(
        App::new()
            .wrap(AuthzTransform::new(
                authz,
                Action::Write,
                ResourceRef::new("doc"),
            ))
            .wrap(fixture::Context {
                identity: Some(identity()),
                fulfilled: Some(vec!["mfa".to_owned()]),
            })
            .route("/", web::get().to(inner)),
    )
    .await;
    let resp = test::call_service(&srv, test::TestRequest::get().uri("/").to_request()).await;
    assert_eq!(resp.status(), StatusCode::OK);
}
