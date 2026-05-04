//! Development-only authentication layer.
//!
//! # WARNING — NOT FOR PRODUCTION
//!
//! `DevAuthLayer` extracts a fixed test subject from the `X-Dev-Subject` request header.
//! It bypasses all real authentication logic and must **never** be deployed in production.
//!
//! The header value is used directly as the `actor_id`. The optional `X-Dev-Tenant` header
//! sets the `tenant_id`. Roles are provided via the `X-Dev-Roles` header as a comma-separated
//! list.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Body;
use http::{Request, Response, StatusCode};
use security_core::identity::AuthenticatedIdentity;
use security_core::types::{ActorId, TenantId};
use time::OffsetDateTime;
use tower::{Layer, Service};
use uuid::Uuid;

use security_core::severity::SecuritySeverity;
use security_events::emit::emit_security_event;
use security_events::event::{EventOutcome, SecurityEvent};
use security_events::kind::EventKind;

/// Tower [`Layer`] that resolves `AuthenticatedIdentity` from development headers.
///
/// # WARNING — NOT FOR PRODUCTION
#[derive(Clone, Debug)]
pub struct DevAuthLayer;

impl<S> Layer<S> for DevAuthLayer {
    type Service = DevAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DevAuthService { inner }
    }
}

/// The service produced by [`DevAuthLayer`].
#[derive(Clone)]
pub struct DevAuthService<S> {
    inner: S,
}

impl<S, ReqBody> Service<Request<ReqBody>> for DevAuthService<S>
where
    S: Service<Request<ReqBody>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let mut inner = self.inner.clone();

        // Check for X-Dev-Subject header
        let actor_str = req
            .headers()
            .get("x-dev-subject")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        match actor_str {
            None => {
                // Emit authn failure event — no subject provided
                let event = SecurityEvent::new(
                    EventKind::AuthnFailure,
                    SecuritySeverity::High,
                    EventOutcome::Failure,
                );
                emit_security_event(event);

                Box::pin(async move {
                    let mut resp = Response::new(Body::empty());
                    *resp.status_mut() = StatusCode::UNAUTHORIZED;
                    Ok(resp)
                })
            }
            Some(actor_str) => {
                // Parse actor_id as UUID or generate one from the string
                let actor_uuid = Uuid::parse_str(&actor_str).unwrap_or_else(|_| Uuid::new_v4());
                let actor_id = ActorId::from(actor_uuid);

                // Parse optional tenant
                let tenant_id = req
                    .headers()
                    .get("x-dev-tenant")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| Uuid::parse_str(s).ok())
                    .map(TenantId::from);

                // Parse optional roles (comma-separated)
                let roles: Vec<String> = req
                    .headers()
                    .get("x-dev-roles")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.split(',').map(|r| r.trim().to_string()).collect())
                    .unwrap_or_default();

                let identity = AuthenticatedIdentity {
                    actor_id,
                    tenant_id,
                    roles,
                    attributes: HashMap::new(),
                    authenticated_at: OffsetDateTime::now_utc(),
                };

                req.extensions_mut().insert(identity);
                Box::pin(async move { inner.call(req).await })
            }
        }
    }
}
