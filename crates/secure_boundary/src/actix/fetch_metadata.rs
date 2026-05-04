//! Actix-web 4 [`FetchMetadataTransform`] — blocks suspicious cross-site
//! browser requests via `Sec-Fetch-*` headers.
//!
//! Behaviorally equivalent to the axum tower [`FetchMetadataLayer`]. Both
//! paths route through the same allow/block classifier so the outcome is
//! identical across frameworks for a given request.
//!
//! [`FetchMetadataLayer`]: crate::fetch_metadata::FetchMetadataLayer

use std::future::{ready, Future, Ready};
use std::pin::Pin;

use actix_web::body::{BoxBody, EitherBody};
use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::StatusCode;
use actix_web::{Error, HttpResponse};
use http::Method;

use crate::fetch_metadata::{classify, emit_cross_site_block, FetchDecision, FetchMetadataLayer};

/// Actix-web 4 middleware builder that enforces Fetch Metadata policy.
///
/// Thin wrapper around [`FetchMetadataLayer`] — same builder methods
/// (`allow_missing_headers`) and same classification semantics.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "actix-web")]
/// # fn _doc() {
/// use actix_web::{web, App, HttpResponse};
/// use secure_boundary::actix::FetchMetadataTransform;
///
/// let _app = App::new()
///     .wrap(FetchMetadataTransform::new())
///     .route("/", web::get().to(|| async { HttpResponse::Ok().finish() }));
/// # }
/// ```
///
/// [`FetchMetadataLayer`]: crate::fetch_metadata::FetchMetadataLayer
#[derive(Clone, Debug, Default)]
pub struct FetchMetadataTransform {
    layer: FetchMetadataLayer,
}

impl FetchMetadataTransform {
    /// Creates a new [`FetchMetadataTransform`] with backward-compatible defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Configures whether requests missing `Sec-Fetch-*` headers are allowed.
    ///
    /// See [`FetchMetadataLayer::allow_missing_headers`].
    ///
    /// [`FetchMetadataLayer::allow_missing_headers`]: crate::fetch_metadata::FetchMetadataLayer::allow_missing_headers
    #[must_use]
    pub fn allow_missing_headers(mut self, allow: bool) -> Self {
        self.layer = self.layer.allow_missing_headers(allow);
        self
    }
}

impl<S, B> Transform<S, ServiceRequest> for FetchMetadataTransform
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type Transform = FetchMetadataMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(FetchMetadataMiddleware {
            service,
            layer: self.layer.clone(),
        }))
    }
}

/// Actix middleware that classifies each request and short-circuits with
/// 403 for cross-site fetches that are not safe top-level navigations.
pub struct FetchMetadataMiddleware<S> {
    service: S,
    layer: FetchMetadataLayer,
}

impl<S, B> Service<ServiceRequest> for FetchMetadataMiddleware<S>
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
        let site = req
            .headers()
            .get("sec-fetch-site")
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);
        let mode = req
            .headers()
            .get("sec-fetch-mode")
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);
        let dest = req
            .headers()
            .get("sec-fetch-dest")
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);

        // Actix's Method type is the same as http::Method as of actix-web 4.
        // Convert via str so the call is tolerant of version drift.
        let method = Method::from_bytes(req.method().as_str().as_bytes()).unwrap_or(Method::GET);

        let decision = classify(
            &method,
            site.as_deref(),
            mode.as_deref(),
            dest.as_deref(),
            self.layer.allow_missing_headers_flag(),
        );

        if matches!(decision, FetchDecision::Block) {
            emit_cross_site_block();
            let (http_req, _payload) = req.into_parts();
            let res = HttpResponse::build(StatusCode::FORBIDDEN)
                .insert_header(("content-type", "application/json"))
                .body(r#"{"error":{"code":"cross_site_request_blocked"}}"#);
            let res = ServiceResponse::new(http_req, res).map_into_right_body();
            return Box::pin(async move { Ok(res) });
        }

        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res.map_into_left_body())
        })
    }
}
