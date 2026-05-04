//! `SecurityStack` — idiomatic middleware composition.
//!
//! Middleware order (outermost → innermost):
//! 1. TraceLayer           — distributed tracing span (applied outermost via separate layer call)
//! 2. CatchPanicLayer      — catch panics, emit 500
//! 3. SetRequestIdLayer    — assign X-Request-Id
//! 4. SecurityHeadersLayer — apply HSTS, CSP, X-Content-Type-Options, etc.
//! 5. TimeoutLayer         — request-level timeout (resilience)
//! 6. ConcurrencyLimitLayer — bulkhead pattern (resilience)
//! 7. DevAuthLayer         — identity resolution (dev only, NOT FOR PRODUCTION)

use std::time::Duration;

use axum::Router;
use http::StatusCode;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use secure_boundary::headers::SecurityHeadersLayer;

use crate::auth_dev::DevAuthLayer;
use crate::resilience::ResilienceConfig;

/// Apply the full security middleware stack to a router.
///
/// `SecurityHeadersLayer` requires `Response<Body>` so `TraceLayer` (which wraps the body
/// type) must be applied as a separate outermost layer, not chained inside the same
/// `ServiceBuilder` as `SecurityHeadersLayer`.
pub fn apply_security_stack(router: Router, resilience: &ResilienceConfig) -> Router {
    let timeout = resilience.request_timeout;
    let concurrency = resilience.concurrency_limit;

    // Inner stack: layers that work with `Response<Body>` directly.
    // In axum, last `.layer()` = outermost (handles request first).
    // Order below: DevAuth is innermost, CatchPanic is outermost of this stack.
    router
        // 7. Dev identity resolution (innermost — applied first so it's closest to handler)
        .layer(DevAuthLayer)
        // 6. Concurrency limit / bulkhead
        .layer(tower::limit::ConcurrencyLimitLayer::new(concurrency))
        // 5. Request timeout
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            timeout,
        ))
        // 4. Security headers on every response
        .layer(SecurityHeadersLayer::default())
        // 3b. Propagate x-request-id to response
        .layer(PropagateRequestIdLayer::x_request_id())
        // 3. Request ID assignment
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        // 2. Panic boundary
        .layer(CatchPanicLayer::new())
        // 1. Distributed tracing (outermost — wraps response body in ResponseBody<...>)
        .layer(TraceLayer::new_for_http())
}

/// Apply a test-friendly middleware stack (shorter timeout, lower concurrency).
pub fn apply_test_security_stack(router: Router) -> Router {
    let resilience = ResilienceConfig::new(Duration::from_secs(5), 10);
    apply_security_stack(router, &resilience)
}
