//! Axum middleware for authorization enforcement.
//!
//! The tower [`Layer`] / [`Service`] implementations here are gated on the
//! `axum` feature. All real work goes through
//! [`crate::enforce::run_check`], which both the axum adapter and the
//! actix-web 4 adapter call so decisions stay identical across frameworks.

#![cfg(feature = "axum")]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum_core::response::Response;
use http::{Request, StatusCode};
use security_core::identity::AuthenticatedIdentity;
use tower::{Layer, Service};

use crate::action::Action;
use crate::enforce::{run_check, EnforceOutcome, ObligationFulfillment};
use crate::enforcer::Authorizer;
use crate::resource::ResourceRef;

/// Tower [`Layer`] that enforces authorization using [`Authorizer`].
///
/// Reads [`AuthenticatedIdentity`] from request extensions (set by a prior auth layer),
/// calls [`crate::enforce::run_check`], and returns 403 Forbidden on `Deny`.
#[derive(Clone)]
pub struct AuthzLayer<A> {
    authorizer: Arc<A>,
    action: Action,
    resource: ResourceRef,
}

impl<A: Authorizer + Send + Sync + 'static> AuthzLayer<A> {
    /// Creates a new `AuthzLayer` guarding the given `action` on `resource`.
    pub fn new(authorizer: Arc<A>, action: Action, resource: ResourceRef) -> Self {
        Self {
            authorizer,
            action,
            resource,
        }
    }
}

impl<A, S> Layer<S> for AuthzLayer<A>
where
    A: Clone,
{
    type Service = AuthzService<A, S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthzService {
            inner,
            authorizer: self.authorizer.clone(),
            action: self.action.clone(),
            resource: self.resource.clone(),
        }
    }
}

/// Tower [`Service`] that performs the authorization check.
#[derive(Clone)]
pub struct AuthzService<A, S> {
    inner: S,
    authorizer: Arc<A>,
    action: Action,
    resource: ResourceRef,
}

impl<A, S, ReqBody> Service<Request<ReqBody>> for AuthzService<A, S>
where
    A: Authorizer + Clone + Send + Sync + 'static,
    S: Service<Request<ReqBody>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let authorizer = self.authorizer.clone();
        let action = self.action.clone();
        let resource = self.resource.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let identity = req.extensions().get::<AuthenticatedIdentity>().cloned();
            let fulfilled = req.extensions().get::<ObligationFulfillment>().cloned();

            let outcome = run_check(
                &*authorizer,
                identity.as_ref(),
                &action,
                &resource,
                fulfilled.as_ref(),
            )
            .await;

            match outcome {
                EnforceOutcome::Allow => inner.call(req).await,
                EnforceOutcome::Deny => Ok(forbidden_response()),
            }
        })
    }
}

fn forbidden_response() -> Response {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::FORBIDDEN;
    resp
}
