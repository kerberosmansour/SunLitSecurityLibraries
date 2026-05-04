//! E2E runtime validation — sg-gate-a M2.
//!
//! Boots a tiny Actix-web 4 service wiring `AuthzTransform` +
//! error-mapping via `impl ResponseError for AppError` and asserts
//! allow, deny, and error-response behaviors end-to-end.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{http::StatusCode, test, web, App, Error, HttpMessage, HttpResponse};
use secure_authz::action::Action;
use secure_authz::actix::AuthzTransform;
use secure_authz::decision::{Decision, DenyReason};
use secure_authz::enforcer::Authorizer;
use secure_authz::resource::ResourceRef;
use secure_authz::subject::Subject;
use secure_errors::kind::AppError;
use security_core::identity::AuthenticatedIdentity;
use security_core::types::{ActorId, TenantId};
use time::OffsetDateTime;
use uuid::Uuid;

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
    type Future = std::future::Ready<Result<Self::Transform, Self::InitError>>;
    fn new_transform(&self, service: S) -> Self::Future {
        std::future::ready(Ok(InjectIdMw {
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
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>>>>;
    forward_ready!(service);
    fn call(&self, req: ServiceRequest) -> Self::Future {
        if let Some(id) = &self.id {
            req.extensions_mut().insert(id.clone());
        }
        Box::pin(self.service.call(req))
    }
}

#[actix_web::test]
async fn actix_service_boots_with_authz_and_error_mapping() {
    let authz = Arc::new(FixedAuthorizer(Decision::Allow {
        obligations: vec![],
    }));
    let _srv = test::init_service(
        App::new()
            .wrap(AuthzTransform::new(
                authz,
                Action::Read,
                ResourceRef::new("item"),
            ))
            .wrap(InjectId(Some(identity())))
            .route(
                "/",
                web::get().to(|| async { Ok::<_, AppError>(HttpResponse::Ok().body("ok")) }),
            ),
    )
    .await;
}

#[actix_web::test]
async fn actix_e2e_authz_allow_reaches_handler() {
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
            .wrap(InjectId(Some(identity())))
            .route(
                "/",
                web::get().to(|| async { Ok::<_, AppError>(HttpResponse::Ok().body("reached")) }),
            ),
    )
    .await;
    let resp = test::call_service(&srv, test::TestRequest::get().uri("/").to_request()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = test::read_body(resp).await;
    assert_eq!(body, actix_web::web::Bytes::from_static(b"reached"));
}

#[actix_web::test]
async fn actix_e2e_authz_deny_returns_403() {
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
            .wrap(InjectId(Some(identity())))
            .route(
                "/",
                web::get().to(|| async { Ok::<_, AppError>(HttpResponse::Ok().body("ok")) }),
            ),
    )
    .await;
    let resp = test::call_service(&srv, test::TestRequest::get().uri("/").to_request()).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn actix_e2e_handler_error_maps_to_response() {
    let srv = test::init_service(App::new().route(
        "/",
        web::get().to(|| async {
            Err::<HttpResponse, _>(AppError::RateLimit {
                retry_after_seconds: Some(30),
            })
        }),
    ))
    .await;
    let resp = test::call_service(&srv, test::TestRequest::get().uri("/").to_request()).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        resp.headers().get("retry-after").unwrap().to_str().unwrap(),
        "30"
    );
}

#[actix_web::test]
async fn actix_e2e_public_error_body_shape() {
    let srv = test::init_service(App::new().route(
        "/",
        web::get().to(|| async { Err::<HttpResponse, _>(AppError::Validation { code: "bad" }) }),
    ))
    .await;
    let resp = test::call_service(&srv, test::TestRequest::get().uri("/").to_request()).await;
    let body = test::read_body(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json.get("code").and_then(|v| v.as_str()),
        Some("invalid_request")
    );
    assert!(json.get("message").is_some());
    // `request_id` is optional; when present it would be an ID, when absent omitted.
    let top_level_keys: Vec<_> = json.as_object().unwrap().keys().cloned().collect();
    for k in &top_level_keys {
        assert!(
            matches!(k.as_str(), "code" | "message" | "request_id"),
            "unexpected key in PublicError: {k}"
        );
    }
}
