//! `secure_smoke_service` — Security smoke-test microservice.
//!
//! A purpose-built axum microservice with 35+ routes, each exercising a specific
//! security control from the SunLit Security Libraries. This is a verification tool,
//! not a demo.

pub mod config;
pub mod routes;
pub mod state;

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::Router;
use secure_boundary::SecurityHeadersLayer;
use secure_errors::middleware::ErrorMappingLayer;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;

use crate::state::AppState;

/// Builds the axum router with all smoke routes and the security middleware stack.
pub fn build_router(state: AppState) -> Router {
    // Input validation routes (no auth required — testing boundary controls)
    let input_routes = Router::new()
        .route("/smoke/xss", post(routes::input::xss_reflect))
        .route("/smoke/sqli", post(routes::input::sqli_check))
        .route("/smoke/cmdi", post(routes::input::cmdi_check))
        .route(
            "/smoke/path-traversal/{*path}",
            get(routes::input::path_traversal_check),
        )
        .route("/smoke/xxe", post(routes::input::xxe_check))
        .route(
            "/smoke/deserialization",
            post(routes::input::deserialization_check),
        )
        .route(
            "/smoke/mass-assignment",
            post(routes::input::mass_assignment_check),
        )
        .route(
            "/smoke/header-injection",
            post(routes::input::header_injection_check),
        )
        .route(
            "/smoke/unicode-bypass",
            post(routes::input::unicode_bypass_check),
        )
        .route("/smoke/body-bomb", post(routes::input::body_bomb_check))
        .route(
            "/smoke/deep-nesting",
            post(routes::input::deep_nesting_check),
        )
        .route("/smoke/field-flood", post(routes::input::field_flood_check));

    // Output encoding routes (no auth required)
    let output_routes = Router::new()
        .route("/smoke/reflect-html", get(routes::output::reflect_html))
        .route("/smoke/reflect-url", get(routes::output::reflect_url))
        .route("/smoke/reflect-json", get(routes::output::reflect_json))
        .route("/smoke/headers", get(routes::output::check_headers));

    // Authentication routes (test auth directly, no middleware auth)
    let auth_routes = Router::new()
        .route("/smoke/auth/jwt", post(routes::auth::jwt_validate))
        .route("/smoke/auth/expired", post(routes::auth::jwt_expired))
        .route("/smoke/auth/alg-none", post(routes::auth::jwt_alg_none))
        .route("/smoke/auth/tampered", post(routes::auth::jwt_tampered))
        .route(
            "/smoke/auth/wrong-issuer",
            post(routes::auth::jwt_wrong_issuer),
        )
        .route("/smoke/auth/session", post(routes::auth::session_lifecycle));

    // Authorization routes (require JWT in Authorization header)
    let authz_routes = Router::new()
        .route("/smoke/authz/allow", get(routes::authz::authz_allow))
        .route("/smoke/authz/deny", get(routes::authz::authz_deny))
        .route(
            "/smoke/authz/cross-tenant",
            get(routes::authz::authz_cross_tenant),
        )
        .route(
            "/smoke/authz/privilege-escalation",
            post(routes::authz::authz_privilege_escalation),
        )
        .route("/smoke/authz/idor", get(routes::authz::authz_idor));

    // Data protection routes
    let data_routes = Router::new()
        .route("/smoke/encrypt", post(routes::data::encrypt_data))
        .route("/smoke/decrypt", post(routes::data::decrypt_data))
        .route(
            "/smoke/decrypt-tampered",
            post(routes::data::decrypt_tampered),
        )
        .route("/smoke/secret-debug", get(routes::data::secret_debug))
        .route("/smoke/key-rotation", post(routes::data::key_rotation));

    // Error handling routes
    let error_routes = Router::new()
        .route("/smoke/error/internal", get(routes::errors::error_internal))
        .route(
            "/smoke/error/dependency",
            get(routes::errors::error_dependency),
        )
        .route("/smoke/error/panic", get(routes::errors::error_panic))
        .route(
            "/smoke/error/validation",
            post(routes::errors::error_validation),
        );

    // Security events routes
    let events_routes = Router::new()
        .route(
            "/smoke/events/log-injection",
            post(routes::events::log_injection),
        )
        .route(
            "/smoke/events/redaction",
            post(routes::events::redaction_check),
        );

    // Mobile security routes (MASVS controls)
    let mobile_routes = Router::new()
        .route(
            "/smoke/mobile/tls-version",
            post(routes::mobile::tls_version_check),
        )
        .route(
            "/smoke/mobile/cert-pin",
            post(routes::mobile::cert_pin_check),
        )
        .route(
            "/smoke/mobile/cleartext",
            post(routes::mobile::cleartext_check),
        )
        .route(
            "/smoke/mobile/storage-policy",
            post(routes::mobile::storage_policy_check),
        )
        .route(
            "/smoke/mobile/sensitive-buffer",
            post(routes::mobile::sensitive_buffer_check),
        )
        .route(
            "/smoke/mobile/biometric",
            post(routes::mobile::biometric_check),
        )
        .route("/smoke/mobile/step-up", post(routes::mobile::step_up_check))
        .route(
            "/smoke/mobile/deep-link",
            post(routes::mobile::deep_link_check),
        )
        .route(
            "/smoke/mobile/webview-url",
            post(routes::mobile::webview_url_check),
        )
        .route(
            "/smoke/mobile/clipboard",
            post(routes::mobile::clipboard_check),
        )
        .route(
            "/smoke/mobile/root-detect",
            post(routes::mobile::root_detect_check),
        )
        .route(
            "/smoke/mobile/app-integrity",
            post(routes::mobile::app_integrity_check),
        )
        .route(
            "/smoke/mobile/pii-classify",
            post(routes::mobile::pii_classify_check),
        )
        .route(
            "/smoke/mobile/pseudonymize",
            post(routes::mobile::pseudonymize_check),
        )
        .route("/smoke/mobile/consent", post(routes::mobile::consent_check));

    // Health check
    let health_route = Router::new()
        .route("/health", get(health))
        .route("/dast-index", get(dast_index));

    // Assemble all routes
    let app = Router::new()
        .merge(input_routes)
        .merge(output_routes)
        .merge(auth_routes)
        .merge(authz_routes)
        .merge(data_routes)
        .merge(error_routes)
        .merge(events_routes)
        .merge(mobile_routes)
        .merge(health_route)
        .layer(DefaultBodyLimit::max(1024 * 1024)) // 1 MiB
        .layer(ErrorMappingLayer)
        .with_state(state);

    // Apply security middleware stack (outermost → innermost for requests)
    app.layer(SecurityHeadersLayer::default())
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(CatchPanicLayer::new())
        .layer(TraceLayer::new_for_http())
}

/// GET `/health` — health check endpoint.
async fn health() -> &'static str {
    "ok"
}

/// GET `/dast-index` — link index for crawl-based DAST scanners (e.g. Dastardly).
///
/// Returns an HTML page with anchor links to every GET route and forms for every
/// POST route so that crawlers can discover the full attack surface without an
/// OpenAPI spec.
async fn dast_index() -> impl axum::response::IntoResponse {
    (
        axum::http::StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        r#"<!DOCTYPE html>
<html><head><title>DAST Index</title></head><body>
<h1>Smoke Service — DAST Crawl Index</h1>

<!-- GET routes (anchor links) -->
<h2>GET</h2>
<ul>
<li><a href="/health">/health</a></li>
<li><a href="/smoke/reflect-html?input=test">/smoke/reflect-html</a></li>
<li><a href="/smoke/reflect-url?input=test">/smoke/reflect-url</a></li>
<li><a href="/smoke/reflect-json?input=test">/smoke/reflect-json</a></li>
<li><a href="/smoke/headers">/smoke/headers</a></li>
<li><a href="/smoke/path-traversal/safe">/smoke/path-traversal</a></li>
<li><a href="/smoke/authz/allow">/smoke/authz/allow</a></li>
<li><a href="/smoke/authz/deny">/smoke/authz/deny</a></li>
<li><a href="/smoke/authz/cross-tenant">/smoke/authz/cross-tenant</a></li>
<li><a href="/smoke/authz/idor?resource_owner=tenant-a">/smoke/authz/idor</a></li>
<li><a href="/smoke/secret-debug">/smoke/secret-debug</a></li>
<li><a href="/smoke/error/internal">/smoke/error/internal</a></li>
<li><a href="/smoke/error/dependency">/smoke/error/dependency</a></li>
<li><a href="/smoke/error/panic">/smoke/error/panic</a></li>
</ul>

<!-- POST routes (forms so crawlers can discover them) -->
<h2>POST</h2>
<form method="POST" action="/smoke/xss"><input name="input" value="test"/><button>xss</button></form>
<form method="POST" action="/smoke/sqli"><input name="input" value="test"/><button>sqli</button></form>
<form method="POST" action="/smoke/cmdi"><input name="input" value="test"/><button>cmdi</button></form>
<form method="POST" action="/smoke/xxe" enctype="text/plain"><input name="input" value="test"/><button>xxe</button></form>
<form method="POST" action="/smoke/deserialization"><input name="input" value="test"/><button>deserialization</button></form>
<form method="POST" action="/smoke/mass-assignment"><input name="input" value="test"/><button>mass-assignment</button></form>
<form method="POST" action="/smoke/header-injection"><input name="input" value="test"/><button>header-injection</button></form>
<form method="POST" action="/smoke/unicode-bypass"><input name="input" value="test"/><button>unicode-bypass</button></form>
<form method="POST" action="/smoke/body-bomb"><input name="input" value="test"/><button>body-bomb</button></form>
<form method="POST" action="/smoke/deep-nesting"><input name="input" value="test"/><button>deep-nesting</button></form>
<form method="POST" action="/smoke/field-flood"><input name="input" value="test"/><button>field-flood</button></form>
<form method="POST" action="/smoke/encrypt"><input name="input" value="test"/><button>encrypt</button></form>
<form method="POST" action="/smoke/decrypt"><input name="input" value="test"/><button>decrypt</button></form>
<form method="POST" action="/smoke/decrypt-tampered"><input name="input" value="test"/><button>decrypt-tampered</button></form>
<form method="POST" action="/smoke/key-rotation"><input name="input" value="test"/><button>key-rotation</button></form>
<form method="POST" action="/smoke/error/validation"><input name="input" value="test"/><button>error/validation</button></form>
<form method="POST" action="/smoke/events/log-injection"><input name="input" value="test"/><button>events/log-injection</button></form>
<form method="POST" action="/smoke/events/redaction"><input name="input" value="test"/><button>events/redaction</button></form>
<form method="POST" action="/smoke/auth/jwt"><input name="token" value="test"/><button>auth/jwt</button></form>
<form method="POST" action="/smoke/auth/expired"><input name="token" value="test"/><button>auth/expired</button></form>
<form method="POST" action="/smoke/auth/alg-none"><input name="token" value="test"/><button>auth/alg-none</button></form>
<form method="POST" action="/smoke/auth/tampered"><input name="token" value="test"/><button>auth/tampered</button></form>
<form method="POST" action="/smoke/auth/wrong-issuer"><input name="token" value="test"/><button>auth/wrong-issuer</button></form>
<form method="POST" action="/smoke/auth/session"><input name="action" value="create"/><button>auth/session</button></form>
<form method="POST" action="/smoke/authz/privilege-escalation"><input name="requested_role" value="admin"/><button>authz/privilege-escalation</button></form>

<!-- Mobile security routes (MASVS) -->
<h2>POST (Mobile)</h2>
<form method="POST" action="/smoke/mobile/tls-version"><input name="version" value="TLS1.3"/><button>mobile/tls-version</button></form>
<form method="POST" action="/smoke/mobile/cert-pin"><input name="cert_hash" value="aabbccdd"/><button>mobile/cert-pin</button></form>
<form method="POST" action="/smoke/mobile/cleartext"><input name="url" value="https://example.com"/><button>mobile/cleartext</button></form>
<form method="POST" action="/smoke/mobile/storage-policy"><input name="classification" value="pii"/><button>mobile/storage-policy</button></form>
<form method="POST" action="/smoke/mobile/sensitive-buffer"><input name="secret" value="test"/><button>mobile/sensitive-buffer</button></form>
<form method="POST" action="/smoke/mobile/biometric"><input name="biometric_class" value="3"/><button>mobile/biometric</button></form>
<form method="POST" action="/smoke/mobile/step-up"><input name="operation" value="transfer"/><button>mobile/step-up</button></form>
<form method="POST" action="/smoke/mobile/deep-link"><input name="url" value="myapp://profile/1"/><button>mobile/deep-link</button></form>
<form method="POST" action="/smoke/mobile/webview-url"><input name="url" value="https://example.com"/><button>mobile/webview-url</button></form>
<form method="POST" action="/smoke/mobile/clipboard"><input name="classification" value="pii"/><button>mobile/clipboard</button></form>
<form method="POST" action="/smoke/mobile/root-detect"><input name="signal_type" value="root"/><button>mobile/root-detect</button></form>
<form method="POST" action="/smoke/mobile/app-integrity"><input name="expected_hash" value="abc"/><button>mobile/app-integrity</button></form>
<form method="POST" action="/smoke/mobile/pii-classify"><input name="data" value="user@test.com"/><button>mobile/pii-classify</button></form>
<form method="POST" action="/smoke/mobile/pseudonymize"><input name="data" value="user@test.com"/><button>mobile/pseudonymize</button></form>
<form method="POST" action="/smoke/mobile/consent"><input name="purpose" value="analytics"/><button>mobile/consent</button></form>
</body></html>
"#,
    )
}
