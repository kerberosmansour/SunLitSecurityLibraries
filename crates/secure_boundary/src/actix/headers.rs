//! Actix-web 4 [`SecurityHeadersTransform`] — injects OWASP-recommended
//! security headers into every response.
//!
//! Behaviorally equivalent to the axum tower [`SecurityHeadersLayer`]. Both
//! paths call the same internal header-pair iterator to build the outgoing
//! response's header set, so headers emitted under the `actix-web` feature
//! are byte-identical to the axum path.
//!
//! [`SecurityHeadersLayer`]: crate::headers::SecurityHeadersLayer

use std::future::{ready, Future, Ready};
use std::pin::Pin;

use actix_web::body::{BoxBody, MessageBody};
use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::Error;
use actix_web::HttpMessage;

use crate::headers::{security_header_pairs, CspNonce, SecurityHeadersLayer};

/// Actix-web 4 middleware builder that injects OWASP-recommended security
/// headers into every response.
///
/// Thin wrapper around [`SecurityHeadersLayer`] — use the same builder
/// methods (`with_csp`, `with_csp_nonce`, `with_permissions_policy`, etc.)
/// and then `.wrap(...)` it onto an `App`.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "actix-web")]
/// # fn _doc() {
/// use actix_web::{web, App, HttpResponse};
/// use secure_boundary::actix::SecurityHeadersTransform;
///
/// let _app = App::new()
///     .wrap(SecurityHeadersTransform::new().with_csp_nonce())
///     .route("/", web::get().to(|| async { HttpResponse::Ok().finish() }));
/// # }
/// ```
///
/// [`SecurityHeadersLayer`]: crate::headers::SecurityHeadersLayer
#[derive(Clone, Debug, Default)]
pub struct SecurityHeadersTransform {
    layer: SecurityHeadersLayer,
}

impl SecurityHeadersTransform {
    /// Creates a new [`SecurityHeadersTransform`] with OWASP-recommended defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Overrides the `Content-Security-Policy` header value.
    ///
    /// See [`SecurityHeadersLayer::with_csp`].
    ///
    /// [`SecurityHeadersLayer::with_csp`]: crate::headers::SecurityHeadersLayer::with_csp
    #[must_use]
    pub fn with_csp(mut self, csp: impl Into<String>) -> Self {
        self.layer = self.layer.with_csp(csp);
        self
    }

    /// Overrides the `Strict-Transport-Security` header value.
    ///
    /// See [`SecurityHeadersLayer::with_hsts`].
    ///
    /// [`SecurityHeadersLayer::with_hsts`]: crate::headers::SecurityHeadersLayer::with_hsts
    #[must_use]
    pub fn with_hsts(mut self, hsts: impl Into<String>) -> Self {
        self.layer = self.layer.with_hsts(hsts);
        self
    }

    /// Enables cryptographically random CSP nonces on each request.
    ///
    /// See [`SecurityHeadersLayer::with_csp_nonce`].
    ///
    /// [`SecurityHeadersLayer::with_csp_nonce`]: crate::headers::SecurityHeadersLayer::with_csp_nonce
    #[must_use]
    pub fn with_csp_nonce(mut self) -> Self {
        self.layer = self.layer.with_csp_nonce();
        self
    }

    /// Overrides the `Permissions-Policy` header value.
    ///
    /// See [`SecurityHeadersLayer::with_permissions_policy`].
    ///
    /// [`SecurityHeadersLayer::with_permissions_policy`]: crate::headers::SecurityHeadersLayer::with_permissions_policy
    #[must_use]
    pub fn with_permissions_policy(mut self, pp: impl Into<String>) -> Self {
        self.layer = self.layer.with_permissions_policy(pp);
        self
    }
}

impl<S, B> Transform<S, ServiceRequest> for SecurityHeadersTransform
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Transform = SecurityHeadersMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SecurityHeadersMiddleware {
            service,
            layer: self.layer.clone(),
        }))
    }
}

/// Actix middleware that applies the [`SecurityHeadersLayer`] configuration
/// on every outgoing response.
///
/// [`SecurityHeadersLayer`]: crate::headers::SecurityHeadersLayer
pub struct SecurityHeadersMiddleware<S> {
    service: S,
    layer: SecurityHeadersLayer,
}

impl<S, B> Service<ServiceRequest> for SecurityHeadersMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let layer = self.layer.clone();
        let nonce = if layer.include_csp_nonce {
            let nonce = CspNonce::generate();
            req.extensions_mut().insert(nonce.clone());
            Some(nonce)
        } else {
            None
        };

        let fut = self.service.call(req);

        Box::pin(async move {
            let res: ServiceResponse<B> = fut.await?;
            let res = res.map_into_boxed_body();
            let (req, mut http_res) = res.into_parts();
            let headers = http_res.headers_mut();
            for (name, value) in security_header_pairs(&layer, nonce.as_ref()) {
                // actix-http pins `http = 0.2`; this crate uses `http = 1.x`.
                // Convert via bytes so we don't carry duplicate types
                // through the public surface.
                let Ok(name_v02) =
                    actix_http::header::HeaderName::from_bytes(name.as_str().as_bytes())
                else {
                    continue;
                };
                let Ok(value_v02) = actix_http::header::HeaderValue::from_bytes(value.as_bytes())
                else {
                    continue;
                };
                headers.insert(name_v02, value_v02);
            }
            Ok(ServiceResponse::new(req, http_res))
        })
    }
}
