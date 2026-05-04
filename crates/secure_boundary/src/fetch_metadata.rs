//! Fetch Metadata request validation middleware.
//!
//! [`FetchMetadataLayer`] blocks suspicious cross-site browser requests using
//! the `Sec-Fetch-*` headers while preserving backward compatibility for older
//! clients that do not send them.
//!
//! The configuration type and the allow/block classifier are framework-neutral.
//! The axum tower [`Layer`] implementation is gated behind the `axum` feature;
//! the actix-web 4 transform wrapping the same configuration lives in
//! [`crate::actix::fetch_metadata`] behind the `actix-web` feature.
//!
//! [`Layer`]: tower::Layer

#[cfg(any(feature = "axum", feature = "actix-web"))]
use http::Method;

#[cfg(any(feature = "axum", feature = "actix-web"))]
use crate::attack_signal::{BoundaryViolation, ViolationKind};

/// Tower [`Layer`] that validates browser Fetch Metadata headers.
///
/// Requests from `same-origin`, `same-site`, and `none` are allowed. Missing
/// `Sec-Fetch-*` headers are also allowed by default for backward compatibility
/// with older browsers. Cross-site requests are blocked unless they are safe
/// top-level navigations.
///
/// # Examples
///
/// ```
/// use secure_boundary::fetch_metadata::FetchMetadataLayer;
///
/// let layer = FetchMetadataLayer::new();
/// # let _ = layer;
/// ```
///
/// [`Layer`]: tower::Layer
#[derive(Clone, Debug)]
#[cfg_attr(not(any(feature = "axum", feature = "actix-web")), allow(dead_code))]
pub struct FetchMetadataLayer {
    allow_missing_headers: bool,
}

impl Default for FetchMetadataLayer {
    fn default() -> Self {
        Self {
            allow_missing_headers: true,
        }
    }
}

impl FetchMetadataLayer {
    /// Creates a new [`FetchMetadataLayer`] with backward-compatible defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Configures whether requests missing `Sec-Fetch-*` headers are allowed.
    #[must_use]
    pub fn allow_missing_headers(mut self, allow_missing_headers: bool) -> Self {
        self.allow_missing_headers = allow_missing_headers;
        self
    }

    /// Returns whether requests missing `Sec-Fetch-*` headers are allowed.
    #[must_use]
    pub fn allow_missing_headers_flag(&self) -> bool {
        self.allow_missing_headers
    }
}

/// Fetch Metadata classification outcome.
#[cfg(any(feature = "axum", feature = "actix-web"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FetchDecision {
    Allow,
    Block,
}

/// Framework-neutral classifier — given the current `Sec-Fetch-*` headers,
/// the HTTP method, and the configuration, decide whether to allow or block.
///
/// Both the axum tower `Service` and the actix-web 4 transform call this so
/// frameworks agree on the allow/block outcome byte-for-byte.
#[cfg(any(feature = "axum", feature = "actix-web"))]
pub(crate) fn classify(
    method: &Method,
    sec_fetch_site: Option<&str>,
    sec_fetch_mode: Option<&str>,
    sec_fetch_dest: Option<&str>,
    allow_missing_headers: bool,
) -> FetchDecision {
    let Some(site) = sec_fetch_site else {
        return if allow_missing_headers {
            FetchDecision::Allow
        } else {
            FetchDecision::Block
        };
    };

    match site {
        "same-origin" | "same-site" | "none" => FetchDecision::Allow,
        "cross-site" => {
            if is_safe_navigation(method, sec_fetch_mode, sec_fetch_dest) {
                FetchDecision::Allow
            } else {
                FetchDecision::Block
            }
        }
        _ => FetchDecision::Block,
    }
}

#[cfg(any(feature = "axum", feature = "actix-web"))]
fn is_safe_navigation(method: &Method, mode: Option<&str>, dest: Option<&str>) -> bool {
    let safe_method = matches!(*method, Method::GET | Method::HEAD);
    let navigation_mode = matches!(mode, Some("navigate"));
    let navigation_dest = matches!(dest, Some("document") | Some("frame") | Some("iframe"));
    safe_method && navigation_mode && navigation_dest
}

/// Emits a `BoundaryViolation` for a blocked cross-site request.
#[cfg(any(feature = "axum", feature = "actix-web"))]
pub(crate) fn emit_cross_site_block() {
    BoundaryViolation::new(
        ViolationKind::SemanticViolation,
        "cross_site_request_blocked",
    )
    .emit();
}

#[cfg(feature = "axum")]
mod axum_impl {
    use super::{classify, emit_cross_site_block, FetchDecision, FetchMetadataLayer};
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use axum::{
        body::Body,
        http::{Request, Response, StatusCode},
    };
    use tower::{Layer, Service};

    impl<S> Layer<S> for FetchMetadataLayer {
        type Service = FetchMetadataService<S>;

        fn layer(&self, inner: S) -> Self::Service {
            FetchMetadataService {
                inner,
                layer: self.clone(),
            }
        }
    }

    /// Tower [`Service`] that enforces Fetch Metadata policy on requests.
    #[derive(Clone, Debug)]
    pub struct FetchMetadataService<S> {
        inner: S,
        layer: FetchMetadataLayer,
    }

    impl<S> Service<Request<Body>> for FetchMetadataService<S>
    where
        S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
        S::Future: Send + 'static,
        S::Error: Send + 'static,
    {
        type Response = Response<Body>;
        type Error = S::Error;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.inner.poll_ready(cx)
        }

        fn call(&mut self, req: Request<Body>) -> Self::Future {
            let site = req
                .headers()
                .get("sec-fetch-site")
                .and_then(|v| v.to_str().ok());
            let mode = req
                .headers()
                .get("sec-fetch-mode")
                .and_then(|v| v.to_str().ok());
            let dest = req
                .headers()
                .get("sec-fetch-dest")
                .and_then(|v| v.to_str().ok());

            let decision = classify(
                req.method(),
                site,
                mode,
                dest,
                self.layer.allow_missing_headers_flag(),
            );

            if matches!(decision, FetchDecision::Block) {
                emit_cross_site_block();
                return Box::pin(async move { Ok(blocked_response()) });
            }

            Box::pin(self.inner.call(req))
        }
    }

    fn blocked_response() -> Response<Body> {
        Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"error":{"code":"cross_site_request_blocked"}}"#,
            ))
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Body::empty())
                    .expect("static fallback response always builds")
            })
    }
}

#[cfg(feature = "axum")]
pub use axum_impl::FetchMetadataService;
