use std::collections::HashMap;

use axum::body::Body;
use axum::Extension;
use http::{Request, StatusCode};
use secure_authz::device_trust::{DeviceTrustContext, DeviceTrustProfile};
use secure_device_trust::{
    AttestationMode, BootstrapBinding, BootstrapIdentity, BootstrapStatus, ClientType,
    DeviceAttestationEvidence, DeviceTrustDecision, DeviceTrustPolicy, DeviceTrustRequest,
    EvidenceFreshness, Platform, ReleaseChannel, TrustTier,
};
use secure_identity::{BoundUserSession, DeviceSessionBinding};
use secure_network::MtlsClientIdentity;
use secure_reference_service::{build_router, resilience::ResilienceConfig, state::AppState};
use security_core::{identity::AuthenticatedIdentity, types::ActorId};
use time::{Duration, OffsetDateTime};
use tower::ServiceExt;
use uuid::Uuid;

async fn router_with_context(context: Option<DeviceTrustContext>) -> axum::Router {
    let state = AppState::new().await;
    let resilience = ResilienceConfig::new(std::time::Duration::from_secs(5), 10);
    let router = build_router(state, &resilience);
    match context {
        Some(context) => router.layer(Extension(context)),
        None => router,
    }
}

fn mtls_identity(serial: &str, fingerprint: &str, trusted_edge: bool) -> MtlsClientIdentity {
    let now = OffsetDateTime::now_utc();
    MtlsClientIdentity::new(
        serial,
        fingerprint,
        now - Duration::minutes(1),
        now + Duration::days(30),
        trusted_edge,
    )
}

fn trust_decision(
    client_type: ClientType,
    platform: Platform,
    attestation_mode: AttestationMode,
    attestation: Option<DeviceAttestationEvidence>,
) -> DeviceTrustDecision {
    DeviceTrustPolicy::production()
        .evaluate(&DeviceTrustRequest {
            bootstrap: BootstrapIdentity {
                app_id: "sunlit-guardian-tauri".to_owned(),
                subject: "CN=sunlit-guardian-tauri,O=Sunlit Guardian,OU=bootstrap-app".to_owned(),
                fingerprint: "bootstrap-fp".to_owned(),
                status: BootstrapStatus::Authorised,
                binding: BootstrapBinding::PerInstall,
            },
            client_type,
            platform,
            release_channel: ReleaseChannel::Dev,
            attestation_mode,
            attestation,
        })
        .expect("fixture trust decision should be valid")
}

fn software_decision() -> DeviceTrustDecision {
    trust_decision(
        ClientType::Desktop,
        Platform::Linux,
        AttestationMode::Off,
        None,
    )
}

fn hardware_decision() -> DeviceTrustDecision {
    trust_decision(
        ClientType::Desktop,
        Platform::MacOs,
        AttestationMode::Monitor,
        Some(DeviceAttestationEvidence {
            provider: "apple-app-attest".to_owned(),
            challenge_id: "fresh-challenge".to_owned(),
            payload_summary: "scrubbed hardware-backed evidence".to_owned(),
            freshness: EvidenceFreshness::Fresh,
        }),
    )
}

fn ci_decision() -> DeviceTrustDecision {
    trust_decision(ClientType::Ci, Platform::Ci, AttestationMode::Off, None)
}

fn identity() -> AuthenticatedIdentity {
    AuthenticatedIdentity {
        actor_id: ActorId::from(Uuid::from_u128(0x33333333333333333333333333333333)),
        tenant_id: None,
        roles: vec!["guardian-user".to_owned()],
        attributes: HashMap::new(),
        authenticated_at: OffsetDateTime::now_utc(),
    }
}

fn bound_session(mtls: &MtlsClientIdentity, tier: TrustTier) -> BoundUserSession {
    let now = OffsetDateTime::now_utc();
    BoundUserSession::new(
        "bus_reference_service_session",
        &identity(),
        DeviceSessionBinding::new(mtls.serial.clone(), mtls.fingerprint.clone(), tier),
        now,
        now + Duration::hours(1),
    )
}

fn context(decision: DeviceTrustDecision, profile: DeviceTrustProfile) -> DeviceTrustContext {
    let mtls = mtls_identity("serial-a", "fp-a", true);
    DeviceTrustContext::new(decision.clone(), mtls.clone())
        .with_bound_user_session(bound_session(&mtls, decision.tier()))
        .with_profile(profile)
}

fn request(path: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .header("x-dev-subject", Uuid::new_v4().to_string())
        .header("x-dev-roles", "admin")
        .body(Body::empty())
        .expect("test request should build")
}

#[tokio::test]
async fn hardware_route_allows_hardware_backed_context() {
    let app = router_with_context(Some(context(
        hardware_decision(),
        DeviceTrustProfile::Production,
    )))
    .await;

    let response = app
        .oneshot(request("/device-trust/hardware"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn hardware_route_denies_software_bound_context() {
    let app = router_with_context(Some(context(
        software_decision(),
        DeviceTrustProfile::Production,
    )))
    .await;

    let response = app
        .oneshot(request("/device-trust/hardware"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn ci_route_allows_software_bound_context_in_test_profile() {
    let app = router_with_context(Some(context(ci_decision(), DeviceTrustProfile::Test))).await;

    let response = app.oneshot(request("/device-trust/ci")).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn ci_route_denies_software_bound_context_in_production_profile() {
    let app =
        router_with_context(Some(context(ci_decision(), DeviceTrustProfile::Production))).await;

    let response = app.oneshot(request("/device-trust/ci")).await.unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn device_trust_routes_deny_when_context_is_missing() {
    let app = router_with_context(None).await;

    let response = app
        .oneshot(request("/device-trust/hardware"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
