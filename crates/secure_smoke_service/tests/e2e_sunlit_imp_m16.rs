//! E2E — Runtime validation for Milestone 16 (Security Smoke-Test Microservice).
//!
//! These tests validate the key integration scenarios from the M16 acceptance
//! table in the runbook. They exercise the full middleware + router stack.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use tower::ServiceExt;

use secure_smoke_service::config::SecurityConfig;
use secure_smoke_service::state::AppState;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: u64,
    iat: u64,
    iss: String,
    aud: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant: Option<String>,
    #[serde(default)]
    roles: Vec<String>,
}

const SECRET: &[u8] = b"smoke-test-secret-key-min-32-bytes!!";

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn valid_token(roles: &[&str]) -> String {
    let now = now_secs();
    let claims = Claims {
        sub: "00000000-0000-0000-0000-000000000001".into(),
        exp: now + 3600,
        iat: now,
        iss: "smoke-test-issuer".into(),
        aud: "smoke-test-audience".into(),
        tenant: Some("00000000-0000-0000-0000-000000000099".into()),
        roles: roles.iter().map(|r| r.to_string()).collect(),
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(SECRET),
    )
    .unwrap()
}

async fn app() -> axum::Router {
    let state = AppState::new(&SecurityConfig::dev()).await.unwrap();
    secure_smoke_service::build_router(state)
}

async fn body_text(resp: axum::http::Response<Body>) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&bytes).to_string()
}

// ── Acceptance scenario 1: XSS payload HTML-encoded ──────────────────────

#[tokio::test]
async fn e2e_xss_html_encoding() {
    let r = app()
        .await
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/smoke/xss")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"content":"<script>alert(1)</script>"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let t = body_text(r).await;
    assert!(t.contains("&lt;script&gt;"), "must HTML-encode <script>");
    assert!(!t.contains("<script>"), "must not contain raw <script>");
}

// ── Acceptance scenario 2: Path traversal rejected ───────────────────────

#[tokio::test]
async fn e2e_path_traversal_rejected() {
    let r = app()
        .await
        .oneshot(
            Request::builder()
                .uri("/smoke/path-traversal/..%2F..%2Fetc%2Fpasswd")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

// ── Acceptance scenario 3: Deep nesting rejected ─────────────────────────

#[tokio::test]
async fn e2e_deep_nesting_rejected() {
    let mut json = String::from(r#"{"value":"#);
    for _ in 0..500 {
        json.push_str(r#"{"a":"#);
    }
    json.push('1');
    for _ in 0..500 {
        json.push('}');
    }
    json.push('}');

    let r = app()
        .await
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/smoke/deep-nesting")
                .header("content-type", "application/json")
                .body(Body::from(json))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(r.status(), StatusCode::OK);
}

// ── Acceptance scenario 4: Valid JWT accepted ────────────────────────────

#[tokio::test]
async fn e2e_valid_jwt_accepted() {
    let token = valid_token(&["admin"]);
    let r = app()
        .await
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/smoke/auth/jwt")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let t = body_text(r).await;
    assert!(t.contains("actor_id"));
}

// ── Acceptance scenario 5: Expired JWT rejected ──────────────────────────

#[tokio::test]
async fn e2e_expired_jwt_rejected() {
    let claims = Claims {
        sub: "00000000-0000-0000-0000-000000000001".into(),
        exp: 1000,
        iat: 999,
        iss: "smoke-test-issuer".into(),
        aud: "smoke-test-audience".into(),
        tenant: None,
        roles: vec![],
    };
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(SECRET),
    )
    .unwrap();

    let r = app()
        .await
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/smoke/auth/expired")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

// ── Acceptance scenario 6: Cross-tenant blocked ──────────────────────────

#[tokio::test]
async fn e2e_cross_tenant_blocked() {
    let token = valid_token(&["admin"]);
    let r = app()
        .await
        .oneshot(
            Request::builder()
                .uri("/smoke/authz/cross-tenant")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
}

// ── Acceptance scenario 7: Tampered ciphertext rejected ──────────────────

#[tokio::test]
async fn e2e_tampered_ciphertext_rejected() {
    let state = AppState::new(&SecurityConfig::dev()).await.unwrap();
    let a = secure_smoke_service::build_router(state);

    // Encrypt
    let r = a
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/smoke/encrypt")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"plaintext":"e2e tamper check"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let envelope_str = body_text(r).await;
    let mut envelope: serde_json::Value = serde_json::from_str(&envelope_str).unwrap();

    // Tamper
    if let Some(ct) = envelope.get_mut("ciphertext") {
        if let Some(arr) = ct.as_array_mut() {
            if let Some(first) = arr.first_mut() {
                let v = first.as_u64().unwrap_or(0);
                *first = serde_json::json!((v + 1) % 256);
            }
        }
    }

    let r = a
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/smoke/decrypt-tampered")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "envelope": envelope }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

// ── Acceptance scenario 8: Panic caught safely ──────────────────────────

#[tokio::test]
async fn e2e_panic_caught_safely() {
    let r = app()
        .await
        .oneshot(
            Request::builder()
                .uri("/smoke/error/panic")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let t = body_text(r).await;
    assert!(!t.contains("deliberate panic"));
}

// ── Acceptance scenario 9: Log injection sanitised ───────────────────────

#[tokio::test]
async fn e2e_log_injection_sanitised() {
    let r = app()
        .await
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/smoke/events/log-injection")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"field":"value\nInjected-log-entry"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

// ── Acceptance scenario 10: All security headers present ─────────────────

#[tokio::test]
async fn e2e_security_headers_present() {
    let r = app()
        .await
        .oneshot(
            Request::builder()
                .uri("/smoke/headers")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let h = r.headers();
    for key in [
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "cross-origin-embedder-policy",
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
    ] {
        assert!(h.contains_key(key), "missing header: {key}");
    }
}
