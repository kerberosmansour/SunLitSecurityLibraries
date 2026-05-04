//! Actix-web 4 [`AuthzTransform`] — enforces authorization via
//! [`crate::enforce::run_check`], returning 403 on `Deny`.
//!
//! Identity-agnostic: depends only on
//! [`security_core::identity::AuthenticatedIdentity`] (retrieved from actix
//! request extensions by an upstream auth middleware). Does not import
//! `secure_identity`.

use std::future::{ready, Future, Ready};
use std::pin::Pin;
use std::sync::Arc;

use actix_web::body::{BoxBody, EitherBody};
use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::StatusCode;
use actix_web::{Error, HttpMessage, HttpResponse};
use security_core::identity::AuthenticatedIdentity;

use crate::action::Action;
use crate::decision::Decision;
use crate::device_trust::{DeviceTrustContext, DeviceTrustRoutePolicy};
use crate::enforce::{run_check, EnforceOutcome, ObligationFulfillment};
use crate::enforcer::Authorizer;
use crate::resource::ResourceRef;

/// Actix-web 4 middleware that enforces authorization using [`Authorizer`].
///
/// Behaviorally equivalent to the axum [`crate::middleware::AuthzLayer`].
/// On every request: extracts the identity from request extensions, calls
/// [`crate::enforce::run_check`], and either forwards to the inner service
/// (Allow) or short-circuits with 403 (Deny / missing identity /
/// unfulfilled obligations).
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "actix-web")]
/// # fn _doc() {
/// use std::sync::Arc;
/// use actix_web::{web, App, HttpResponse};
/// use secure_authz::action::Action;
/// use secure_authz::actix::AuthzTransform;
/// use secure_authz::resource::ResourceRef;
/// use secure_authz::testkit::MockAuthorizer;
///
/// let authz = Arc::new(MockAuthorizer::allow());
/// let _app = App::new()
///     .wrap(AuthzTransform::new(authz, Action::Read, ResourceRef::new("item")))
///     .route("/", web::get().to(|| async { HttpResponse::Ok().finish() }));
/// # }
/// ```
#[derive(Clone)]
pub struct AuthzTransform<A> {
    authorizer: Arc<A>,
    action: Action,
    resource: ResourceRef,
}

impl<A: Authorizer + Send + Sync + 'static> AuthzTransform<A> {
    /// Creates a new [`AuthzTransform`] guarding the given `action` on
    /// `resource`.
    #[must_use]
    pub fn new(authorizer: Arc<A>, action: Action, resource: ResourceRef) -> Self {
        Self {
            authorizer,
            action,
            resource,
        }
    }
}

/// Actix-web 4 middleware that enforces [`DeviceTrustRoutePolicy`].
///
/// An upstream mTLS/device-trust layer must insert [`DeviceTrustContext`] into
/// request extensions. Missing context, untrusted edge metadata, revoked
/// context, tier mismatch, or bound-session mismatch all short-circuit with
/// `403`.
#[derive(Clone)]
pub struct DeviceTrustTransform {
    policy: DeviceTrustRoutePolicy,
}

impl DeviceTrustTransform {
    /// Creates a new device-trust middleware for the route policy.
    #[must_use]
    pub fn new(policy: DeviceTrustRoutePolicy) -> Self {
        Self { policy }
    }
}

impl<S, B> Transform<S, ServiceRequest> for DeviceTrustTransform
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type Transform = DeviceTrustMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(DeviceTrustMiddleware {
            service: std::rc::Rc::new(service),
            policy: self.policy.clone(),
        }))
    }
}

/// Actix middleware built by [`DeviceTrustTransform::new_transform`].
pub struct DeviceTrustMiddleware<S> {
    service: std::rc::Rc<S>,
    policy: DeviceTrustRoutePolicy,
}

impl<S, B> Service<ServiceRequest> for DeviceTrustMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let policy = self.policy.clone();
        let context = req.extensions().get::<DeviceTrustContext>().cloned();

        Box::pin(async move {
            match policy.evaluate(context.as_ref()) {
                Decision::Allow { .. } => {
                    let resp = service.call(req).await?;
                    Ok(resp.map_into_left_body())
                }
                Decision::Deny { .. } => {
                    let (http_req, _payload) = req.into_parts();
                    let res = HttpResponse::build(StatusCode::FORBIDDEN)
                        .body(actix_web::body::BoxBody::new(String::new()));
                    let res = ServiceResponse::new(http_req, res).map_into_right_body();
                    Ok(res)
                }
            }
        })
    }
}

impl<S, B, A> Transform<S, ServiceRequest> for AuthzTransform<A>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    A: Authorizer + Send + Sync + 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type Transform = AuthzMiddleware<S, A>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthzMiddleware {
            service: std::rc::Rc::new(service),
            authorizer: self.authorizer.clone(),
            action: self.action.clone(),
            resource: self.resource.clone(),
        }))
    }
}

/// Actix middleware built by [`AuthzTransform::new_transform`].
pub struct AuthzMiddleware<S, A> {
    service: std::rc::Rc<S>,
    authorizer: Arc<A>,
    action: Action,
    resource: ResourceRef,
}

impl<S, B, A> Service<ServiceRequest> for AuthzMiddleware<S, A>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    A: Authorizer + Send + Sync + 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let authorizer = self.authorizer.clone();
        let action = self.action.clone();
        let resource = self.resource.clone();

        let identity = req.extensions().get::<AuthenticatedIdentity>().cloned();
        let fulfilled = req.extensions().get::<ObligationFulfillment>().cloned();

        Box::pin(async move {
            let outcome = run_check(
                &*authorizer,
                identity.as_ref(),
                &action,
                &resource,
                fulfilled.as_ref(),
            )
            .await;

            match outcome {
                EnforceOutcome::Allow => {
                    let resp = service.call(req).await?;
                    Ok(resp.map_into_left_body())
                }
                EnforceOutcome::Deny => {
                    let (http_req, _payload) = req.into_parts();
                    let res = HttpResponse::build(StatusCode::FORBIDDEN)
                        .body(actix_web::body::BoxBody::new(String::new()));
                    let res = ServiceResponse::new(http_req, res).map_into_right_body();
                    Ok(res)
                }
            }
        })
    }
}
