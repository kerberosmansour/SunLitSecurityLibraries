//! Security headers middleware.
//!
//! [`SecurityHeadersLayer`] injects OWASP-recommended security headers into
//! every HTTP response and can optionally attach a per-request CSP nonce.
//!
//! The configuration type ([`SecurityHeadersLayer`]) and helpers
//! ([`CspNonce`], [`defaults`]) are framework-neutral. The tower [`Layer`]
//! implementation targeting axum is gated behind the `axum` feature; the
//! matching actix-web 4 transform lives in [`crate::actix::headers`]
//! behind the `actix-web` feature.
//!
//! [`Layer`]: tower::Layer

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use uuid::Uuid;

/// Default security header values.
pub mod defaults {
    /// Default `Strict-Transport-Security` value (2 years, includeSubDomains, preload).
    pub const HSTS: &str = "max-age=63072000; includeSubDomains; preload";
    /// Default `Content-Security-Policy` value.
    pub const CSP: &str = "default-src 'none'; frame-ancestors 'none'";
    /// Default `X-Content-Type-Options` value.
    pub const XCTO: &str = "nosniff";
    /// Default `X-Frame-Options` value.
    pub const XFO: &str = "DENY";
    /// Default `Permissions-Policy` value.
    pub const PERMISSIONS_POLICY: &str = "camera=(), microphone=(), geolocation=()";
    /// Default `Cache-Control` value.
    pub const CACHE_CONTROL: &str = "no-store";
    /// Default `Cross-Origin-Embedder-Policy` value.
    pub const COEP: &str = "require-corp";
    /// Default `Cross-Origin-Opener-Policy` value.
    pub const COOP: &str = "same-origin";
    /// Default `Cross-Origin-Resource-Policy` value.
    pub const CORP: &str = "same-origin";
    /// Default `X-DNS-Prefetch-Control` value.
    pub const X_DNS_PREFETCH_CONTROL: &str = "off";
    /// Default `X-Permitted-Cross-Domain-Policies` value.
    pub const X_PERMITTED_CROSS_DOMAIN_POLICIES: &str = "none";
}

/// A per-request nonce for Content Security Policy directives.
///
/// # Examples
///
/// ```
/// use secure_boundary::headers::CspNonce;
///
/// let nonce = CspNonce::from("abc123");
/// assert_eq!(nonce.as_str(), "abc123");
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[must_use]
pub struct CspNonce(String);

impl CspNonce {
    /// Generates a cryptographically random CSP nonce.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_boundary::headers::CspNonce;
    ///
    /// let nonce = CspNonce::generate();
    /// assert!(!nonce.as_str().is_empty());
    /// ```
    pub fn generate() -> Self {
        Self(STANDARD_NO_PAD.encode(Uuid::new_v4().as_bytes()))
    }

    /// Returns the nonce as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for CspNonce {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<&str> for CspNonce {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

/// Tower [`Layer`] that injects OWASP-recommended security headers into every response.
///
/// Framework-neutral configuration container. The axum/tower integration is
/// gated on the `axum` feature; the actix-web 4 transform wrapping the same
/// configuration is [`crate::actix::headers::SecurityHeadersTransform`],
/// gated on the `actix-web` feature. Both frameworks emit byte-identical
/// headers for a given [`SecurityHeadersLayer`].
///
/// All default values follow OWASP recommendations. Individual headers can be
/// overridden via builder methods.
///
/// This type is `Clone + Send + Sync + 'static`.
///
/// # Examples
///
/// ```
/// use secure_boundary::headers::SecurityHeadersLayer;
///
/// // Create with OWASP-recommended defaults.
/// let layer = SecurityHeadersLayer::new();
///
/// // Customise individual headers via builder methods.
/// let layer = SecurityHeadersLayer::new()
///     .with_csp("default-src 'self'")
///     .with_csp_nonce();
/// # let _ = layer;
/// ```
///
/// [`Layer`]: tower::Layer
#[derive(Clone, Debug)]
#[allow(dead_code)] // Fields are only read when a framework feature is enabled.
pub struct SecurityHeadersLayer {
    csp: String,
    hsts: String,
    xcto: String,
    xfo: String,
    permissions_policy: String,
    cache_control: String,
    coep: String,
    coop: String,
    corp: String,
    x_dns_prefetch_control: String,
    x_permitted_cross_domain_policies: String,
    pub(crate) include_csp_nonce: bool,
}

impl Default for SecurityHeadersLayer {
    fn default() -> Self {
        Self {
            csp: defaults::CSP.to_owned(),
            hsts: defaults::HSTS.to_owned(),
            xcto: defaults::XCTO.to_owned(),
            xfo: defaults::XFO.to_owned(),
            permissions_policy: defaults::PERMISSIONS_POLICY.to_owned(),
            cache_control: defaults::CACHE_CONTROL.to_owned(),
            coep: defaults::COEP.to_owned(),
            coop: defaults::COOP.to_owned(),
            corp: defaults::CORP.to_owned(),
            x_dns_prefetch_control: defaults::X_DNS_PREFETCH_CONTROL.to_owned(),
            x_permitted_cross_domain_policies: defaults::X_PERMITTED_CROSS_DOMAIN_POLICIES
                .to_owned(),
            include_csp_nonce: false,
        }
    }
}

impl SecurityHeadersLayer {
    /// Creates a new [`SecurityHeadersLayer`] with OWASP-recommended defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Overrides the `Content-Security-Policy` header value.
    ///
    /// When [`SecurityHeadersLayer::with_csp_nonce`] is enabled, a `{nonce}`
    /// placeholder in the provided policy will be replaced with the generated
    /// per-request nonce.
    #[must_use]
    pub fn with_csp(mut self, csp: impl Into<String>) -> Self {
        self.csp = csp.into();
        self
    }

    /// Overrides the `Strict-Transport-Security` header value.
    #[must_use]
    pub fn with_hsts(mut self, hsts: impl Into<String>) -> Self {
        self.hsts = hsts.into();
        self
    }

    /// Enables cryptographically random CSP nonces on each request.
    ///
    /// If the configured CSP contains `{nonce}`, that placeholder is replaced.
    /// Otherwise secure nonce-based `script-src` and `style-src` directives are
    /// appended automatically.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_boundary::headers::SecurityHeadersLayer;
    ///
    /// let layer = SecurityHeadersLayer::new().with_csp_nonce();
    /// # let _ = layer;
    /// ```
    #[must_use]
    pub fn with_csp_nonce(mut self) -> Self {
        self.include_csp_nonce = true;
        self
    }

    /// Overrides the `Permissions-Policy` header value.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_boundary::headers::SecurityHeadersLayer;
    ///
    /// let layer = SecurityHeadersLayer::new().with_permissions_policy("camera=(self)");
    /// # let _ = layer;
    /// ```
    #[must_use]
    pub fn with_permissions_policy(mut self, permissions_policy: impl Into<String>) -> Self {
        self.permissions_policy = permissions_policy.into();
        self
    }

    #[cfg_attr(not(any(feature = "axum", feature = "actix-web")), allow(dead_code))]
    pub(crate) fn csp_value(&self, nonce: Option<&CspNonce>) -> String {
        match nonce {
            Some(nonce) if self.csp.contains("{nonce}") => {
                self.csp.replace("{nonce}", nonce.as_str())
            }
            Some(nonce) => format!(
                "{}; script-src 'nonce-{}'; style-src 'nonce-{}'",
                self.csp,
                nonce.as_str(),
                nonce.as_str()
            ),
            None => self.csp.clone(),
        }
    }
}

/// Returns the full set of (`HeaderName`, `HeaderValue`) pairs that should
/// be inserted into an outgoing response's header map for this
/// [`SecurityHeadersLayer`] configuration.
///
/// Framework-neutral — each HTTP framework's adapter inserts these into its
/// own header-map type. `http::HeaderName` and `http::HeaderValue` are used
/// here because both axum (via `http`) and actix-web 4 (via `actix-http`
/// re-exporting `http`) agree on these types.
///
/// `nonce` is passed only when [`SecurityHeadersLayer::with_csp_nonce`] is
/// enabled and a nonce has been generated for the current request.
#[cfg(any(feature = "axum", feature = "actix-web"))]
pub(crate) fn security_header_pairs(
    layer: &SecurityHeadersLayer,
    nonce: Option<&CspNonce>,
) -> Vec<(http::HeaderName, http::HeaderValue)> {
    use http::header::{
        HeaderName, HeaderValue, CACHE_CONTROL, STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS,
        X_FRAME_OPTIONS,
    };

    fn hv(s: &str) -> HeaderValue {
        HeaderValue::from_str(s).expect("security header value is always valid ASCII")
    }

    vec![
        (STRICT_TRANSPORT_SECURITY, hv(&layer.hsts)),
        (
            HeaderName::from_static("content-security-policy"),
            hv(&layer.csp_value(nonce)),
        ),
        (X_CONTENT_TYPE_OPTIONS, hv(&layer.xcto)),
        (X_FRAME_OPTIONS, hv(&layer.xfo)),
        (
            HeaderName::from_static("permissions-policy"),
            hv(&layer.permissions_policy),
        ),
        (CACHE_CONTROL, hv(&layer.cache_control)),
        (
            HeaderName::from_static("cross-origin-embedder-policy"),
            hv(&layer.coep),
        ),
        (
            HeaderName::from_static("cross-origin-opener-policy"),
            hv(&layer.coop),
        ),
        (
            HeaderName::from_static("cross-origin-resource-policy"),
            hv(&layer.corp),
        ),
        (
            HeaderName::from_static("x-dns-prefetch-control"),
            hv(&layer.x_dns_prefetch_control),
        ),
        (
            HeaderName::from_static("x-permitted-cross-domain-policies"),
            hv(&layer.x_permitted_cross_domain_policies),
        ),
    ]
}

#[cfg(feature = "axum")]
mod axum_impl {
    use super::{security_header_pairs, CspNonce, SecurityHeadersLayer};
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use axum::{
        body::Body,
        http::{Request, Response},
    };
    use tower::{Layer, Service};

    impl<S> Layer<S> for SecurityHeadersLayer {
        type Service = SecurityHeadersService<S>;

        fn layer(&self, inner: S) -> Self::Service {
            SecurityHeadersService {
                inner,
                layer: self.clone(),
            }
        }
    }

    /// Tower [`Service`] that injects security headers into HTTP responses.
    #[derive(Clone, Debug)]
    pub struct SecurityHeadersService<S> {
        inner: S,
        layer: SecurityHeadersLayer,
    }

    impl<S> Service<Request<Body>> for SecurityHeadersService<S>
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

        fn call(&mut self, mut req: Request<Body>) -> Self::Future {
            let layer = self.layer.clone();
            let nonce = if layer.include_csp_nonce {
                let nonce = CspNonce::generate();
                req.extensions_mut().insert(nonce.clone());
                Some(nonce)
            } else {
                None
            };
            let fut = self.inner.call(req);
            Box::pin(async move {
                let mut resp = fut.await?;
                let headers = resp.headers_mut();
                for (name, value) in security_header_pairs(&layer, nonce.as_ref()) {
                    headers.insert(name, value);
                }
                Ok(resp)
            })
        }
    }
}

#[cfg(feature = "axum")]
pub use axum_impl::SecurityHeadersService;
