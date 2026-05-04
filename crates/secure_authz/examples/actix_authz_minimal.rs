//! Minimal Actix-web 4 service using `secure_authz::actix::AuthzTransform`.
//!
//! Build and run:
//!
//! ```sh
//! cargo run --example actix_authz_minimal -p secure_authz --features actix-web
//! ```
//!
//! This example:
//! 1. Registers a tiny upstream middleware that synthesises an
//!    `AuthenticatedIdentity` from a hardcoded header (stand-in for a real
//!    JWT-validating middleware like `secure_identity`).
//! 2. Wraps `AuthzTransform` guarding `Action::Read` on a `ResourceRef`.
//! 3. Uses the `MockAuthorizer` from `secure_authz::testkit` to return
//!    `Decision::Allow`.
//!
//! Test it with:
//!
//! ```sh
//! # Identity present (allow) — returns 200
//! curl -v http://127.0.0.1:8080/items -H "x-mock-identity: alice"
//!
//! # No identity (deny) — returns 403
//! curl -v http://127.0.0.1:8080/items
//! ```

use std::sync::Arc;

use actix_web::{web, App, HttpResponse, HttpServer};
use secure_authz::action::Action;
use secure_authz::actix::AuthzTransform;
use secure_authz::resource::ResourceRef;
use secure_authz::testkit::MockAuthorizer;

async fn items() -> HttpResponse {
    HttpResponse::Ok().body("you may read items")
}

mod upstream_auth {
    //! Example upstream auth middleware that turns the `x-mock-identity`
    //! header into an `AuthenticatedIdentity`. In production this would be
    //! a JWT validator (e.g. `secure_identity`).

    use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
    use actix_web::{Error, HttpMessage};
    use security_core::identity::AuthenticatedIdentity;
    use security_core::types::{ActorId, TenantId};
    use std::future::{ready, Future, Ready};
    use std::pin::Pin;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Clone, Default)]
    pub struct MockAuth;

    impl<S, B> Transform<S, ServiceRequest> for MockAuth
    where
        S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
        S::Future: 'static,
        B: 'static,
    {
        type Response = ServiceResponse<B>;
        type Error = Error;
        type Transform = MockAuthMw<S>;
        type InitError = ();
        type Future = Ready<Result<Self::Transform, Self::InitError>>;
        fn new_transform(&self, service: S) -> Self::Future {
            ready(Ok(MockAuthMw { service }))
        }
    }

    pub struct MockAuthMw<S> {
        service: S,
    }

    impl<S, B> Service<ServiceRequest> for MockAuthMw<S>
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
            if req.headers().contains_key("x-mock-identity") {
                req.extensions_mut().insert(AuthenticatedIdentity {
                    actor_id: ActorId::from(Uuid::new_v4()),
                    tenant_id: Some(TenantId::from(Uuid::new_v4())),
                    roles: vec!["reader".to_owned()],
                    attributes: Default::default(),
                    authenticated_at: OffsetDateTime::now_utc(),
                });
            }
            Box::pin(self.service.call(req))
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        let authz = Arc::new(MockAuthorizer::allow());
        App::new()
            // AuthzTransform runs AFTER upstream_auth::MockAuth so the
            // identity is already in extensions when AuthzTransform reads it.
            .wrap(AuthzTransform::new(
                authz,
                Action::Read,
                ResourceRef::new("item"),
            ))
            .wrap(upstream_auth::MockAuth)
            .route("/items", web::get().to(items))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
