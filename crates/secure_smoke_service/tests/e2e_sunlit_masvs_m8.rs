//! E2E — Runtime validation for Milestone 8 (Mobile Smoke Routes).
//!
//! These tests validate the BDD acceptance scenarios and E2E runtime
//! validations from the M8 runbook. They exercise the full middleware +
//! router stack for all 15 mobile security routes.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use secure_smoke_service::config::SecurityConfig;
use secure_smoke_service::state::AppState;

async fn app() -> axum::Router {
    let state = AppState::new(&SecurityConfig::dev()).await.unwrap();
    secure_smoke_service::build_router(state)
}

async fn body_text(resp: axum::http::Response<Body>) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&bytes).to_string()
}

fn json_post(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

// ── E2E: test_all_mobile_routes_respond ──────────────────────────────────

#[tokio::test]
async fn test_all_mobile_routes_respond() {
    let payloads: &[(&str, &str)] = &[
        ("/smoke/mobile/tls-version", r#"{"version":"TLS1.3"}"#),
        (
            "/smoke/mobile/cert-pin",
            r#"{"cert_hash":"aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"}"#,
        ),
        (
            "/smoke/mobile/cleartext",
            r#"{"url":"https://example.com"}"#,
        ),
        (
            "/smoke/mobile/storage-policy",
            r#"{"classification":"pii","is_encrypted":true,"has_hardware_keystore":false}"#,
        ),
        (
            "/smoke/mobile/sensitive-buffer",
            r#"{"secret":"my-secret-value"}"#,
        ),
        (
            "/smoke/mobile/biometric",
            r#"{"biometric_class":3,"crypto_binding":{"key_id":"k1","enrollment_id":"e1"},"device_credential_fallback":false,"current_enrollment_id":"e1"}"#,
        ),
        (
            "/smoke/mobile/step-up",
            r#"{"operation":"transfer","last_auth_age_secs":60}"#,
        ),
        ("/smoke/mobile/deep-link", r#"{"url":"myapp://profile/1"}"#),
        (
            "/smoke/mobile/webview-url",
            r#"{"url":"https://example.com/page"}"#,
        ),
        ("/smoke/mobile/clipboard", r#"{"classification":"pii"}"#),
        (
            "/smoke/mobile/root-detect",
            r#"{"signal_type":"root","confidence":"high","evidence":"su binary"}"#,
        ),
        (
            "/smoke/mobile/app-integrity",
            r#"{"expected_hash":"abc123","actual_hash":"abc123"}"#,
        ),
        ("/smoke/mobile/pii-classify", r#"{"data":"user@test.com"}"#),
        (
            "/smoke/mobile/pseudonymize",
            r#"{"data":"user@test.com","salt":"test-salt"}"#,
        ),
        (
            "/smoke/mobile/consent",
            r#"{"purpose":"analytics","consent_state":"granted","requested_purpose":"analytics"}"#,
        ),
    ];

    for (uri, body) in payloads {
        let r = app().await.oneshot(json_post(uri, body)).await.unwrap();
        let status = r.status();
        assert!(
            status == StatusCode::OK || status == StatusCode::UNPROCESSABLE_ENTITY,
            "Route {uri} returned unexpected status: {status}"
        );
    }
}

// ── E2E: test_mobile_routes_require_valid_json ───────────────────────────

#[tokio::test]
async fn test_mobile_routes_require_valid_json() {
    let routes = [
        "/smoke/mobile/tls-version",
        "/smoke/mobile/cert-pin",
        "/smoke/mobile/cleartext",
        "/smoke/mobile/storage-policy",
        "/smoke/mobile/sensitive-buffer",
        "/smoke/mobile/biometric",
        "/smoke/mobile/step-up",
        "/smoke/mobile/deep-link",
        "/smoke/mobile/webview-url",
        "/smoke/mobile/clipboard",
        "/smoke/mobile/root-detect",
        "/smoke/mobile/app-integrity",
        "/smoke/mobile/pii-classify",
        "/smoke/mobile/pseudonymize",
        "/smoke/mobile/consent",
    ];

    for uri in routes {
        let r = app()
            .await
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from("invalid-json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            r.status().is_client_error(),
            "Route {uri} should reject invalid JSON, got {}",
            r.status()
        );
    }
}

// ── E2E: test_attack_payloads_rejected ───────────────────────────────────

#[tokio::test]
async fn test_attack_payloads_rejected() {
    let attacks: &[(&str, &str, StatusCode)] = &[
        // TLS 1.0 should be rejected
        (
            "/smoke/mobile/tls-version",
            r#"{"version":"TLS1.0"}"#,
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        // javascript: deep link should be rejected
        (
            "/smoke/mobile/deep-link",
            r#"{"url":"javascript:alert(1)"}"#,
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        // file:// WebView URL should be rejected
        (
            "/smoke/mobile/webview-url",
            r#"{"url":"file:///etc/passwd"}"#,
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        // HTTP cleartext should be blocked
        (
            "/smoke/mobile/cleartext",
            r#"{"url":"http://evil.com/api"}"#,
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        // Step-up required when auth is stale (10 min > 5 min max)
        (
            "/smoke/mobile/step-up",
            r#"{"operation":"transfer","last_auth_age_secs":600}"#,
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        // Tampered integrity hash
        (
            "/smoke/mobile/app-integrity",
            r#"{"expected_hash":"abc123","actual_hash":"xyz789"}"#,
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        // Consent denied
        (
            "/smoke/mobile/consent",
            r#"{"purpose":"analytics","consent_state":"denied","requested_purpose":"analytics"}"#,
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
    ];

    for (uri, body, expected_status) in attacks {
        let r = app().await.oneshot(json_post(uri, body)).await.unwrap();
        assert_eq!(
            r.status(),
            *expected_status,
            "Attack payload on {uri} should return {expected_status}, got {}",
            r.status()
        );
    }
}

// ── E2E: test_security_events_emitted ────────────────────────────────────

#[tokio::test]
async fn test_security_events_emitted() {
    // Root detection route emits security events via InMemorySink
    let r = app()
        .await
        .oneshot(json_post(
            "/smoke/mobile/root-detect",
            r#"{"signal_type":"root","confidence":"high","evidence":"su binary found"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let t = body_text(r).await;
    let json: serde_json::Value = serde_json::from_str(&t).unwrap();
    assert!(
        json["events_emitted"].as_u64().unwrap_or(0) > 0,
        "Root detect should emit security events"
    );

    // App integrity failure emits events
    let r = app()
        .await
        .oneshot(json_post(
            "/smoke/mobile/app-integrity",
            r#"{"expected_hash":"abc","actual_hash":"def"}"#,
        ))
        .await
        .unwrap();
    let t = body_text(r).await;
    let json: serde_json::Value = serde_json::from_str(&t).unwrap();
    assert!(
        json["events_emitted"].as_u64().unwrap_or(0) > 0,
        "Integrity failure should emit security events"
    );
}

// ── BDD: TLS version validation rejects TLS 1.0 ─────────────────────────

#[tokio::test]
async fn bdd_tls_version_rejects_tls10() {
    let r = app()
        .await
        .oneshot(json_post(
            "/smoke/mobile/tls-version",
            r#"{"version":"TLS1.0"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let t = body_text(r).await;
    assert!(t.contains("tls_version_rejected"));
}

// ── BDD: Cert pin validates known hash ───────────────────────────────────

#[tokio::test]
async fn bdd_cert_pin_validates_known_hash() {
    let r = app()
        .await
        .oneshot(json_post(
            "/smoke/mobile/cert-pin",
            r#"{"cert_hash":"aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let t = body_text(r).await;
    assert!(t.contains("pin_valid"));
}

// ── BDD: Deep link validates safe URL ────────────────────────────────────

#[tokio::test]
async fn bdd_deep_link_validates_safe_url() {
    let r = app()
        .await
        .oneshot(json_post(
            "/smoke/mobile/deep-link",
            r#"{"url":"myapp://profile/1"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let t = body_text(r).await;
    assert!(t.contains("valid_deep_link"));
}

// ── BDD: Deep link rejects javascript scheme ─────────────────────────────

#[tokio::test]
async fn bdd_deep_link_rejects_javascript_scheme() {
    let r = app()
        .await
        .oneshot(json_post(
            "/smoke/mobile/deep-link",
            r#"{"url":"javascript:alert(1)"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let t = body_text(r).await;
    assert!(t.contains("dangerous_scheme"));
}

// ── BDD: PII classifier detects email ────────────────────────────────────

#[tokio::test]
async fn bdd_pii_classifier_detects_email() {
    let r = app()
        .await
        .oneshot(json_post(
            "/smoke/mobile/pii-classify",
            r#"{"data":"user@test.com"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let t = body_text(r).await;
    let json: serde_json::Value = serde_json::from_str(&t).unwrap();
    assert_eq!(json["classification"], "email");
}

// ── BDD: Pseudonymizer returns consistent hash ──────────────────────────

#[tokio::test]
async fn bdd_pseudonymizer_returns_consistent_hash() {
    let body = r#"{"data":"user@test.com","salt":"test-salt"}"#;
    let r1 = app()
        .await
        .oneshot(json_post("/smoke/mobile/pseudonymize", body))
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::OK);
    let t1 = body_text(r1).await;
    let j1: serde_json::Value = serde_json::from_str(&t1).unwrap();

    let r2 = app()
        .await
        .oneshot(json_post("/smoke/mobile/pseudonymize", body))
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::OK);
    let t2 = body_text(r2).await;
    let j2: serde_json::Value = serde_json::from_str(&t2).unwrap();

    assert_eq!(
        j1["value"], j2["value"],
        "Same input + salt must produce same pseudonymized value"
    );
}

// ── BDD: Root detection signal processed ─────────────────────────────────

#[tokio::test]
async fn bdd_root_detection_signal_processed() {
    let r = app()
        .await
        .oneshot(json_post(
            "/smoke/mobile/root-detect",
            r#"{"signal_type":"root","confidence":"high","evidence":"su binary found"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let t = body_text(r).await;
    assert!(t.contains("rasp_decision"));
}

// ── BDD: All existing routes still work ──────────────────────────────────

#[tokio::test]
async fn bdd_existing_health_route_works() {
    let r = app()
        .await
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let t = body_text(r).await;
    assert_eq!(t, "ok");
}
