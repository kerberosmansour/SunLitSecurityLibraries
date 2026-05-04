use std::collections::HashMap;

use secure_authz::{
    action::Action,
    decision::{Decision, DenyReason},
    device_trust::{
        DeviceTrustContext, DeviceTrustProfile, DeviceTrustRequirement, DeviceTrustRoutePolicy,
    },
    resource::ResourceRef,
};
use secure_device_trust::{
    AttestationMode, BootstrapBinding, BootstrapIdentity, BootstrapStatus, ClientType,
    DeviceAttestationEvidence, DeviceTrustDecision, DeviceTrustPolicy, DeviceTrustRequest,
    EvidenceFreshness, Platform, ReleaseChannel, TrustTier,
};
use secure_identity::{BoundUserSession, DeviceSessionBinding};
use secure_network::MtlsClientIdentity;
use security_core::{identity::AuthenticatedIdentity, types::ActorId};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

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
        actor_id: ActorId::from(Uuid::from_u128(0x22222222222222222222222222222222)),
        tenant_id: None,
        roles: vec!["guardian-user".to_owned()],
        attributes: HashMap::new(),
        authenticated_at: OffsetDateTime::now_utc(),
    }
}

fn bound_session(mtls: &MtlsClientIdentity, tier: TrustTier) -> BoundUserSession {
    let now = OffsetDateTime::now_utc();
    BoundUserSession::new(
        "bus_test_session",
        &identity(),
        DeviceSessionBinding::new(mtls.serial.clone(), mtls.fingerprint.clone(), tier),
        now,
        now + Duration::hours(1),
    )
}

fn policy(requirement: DeviceTrustRequirement) -> DeviceTrustRoutePolicy {
    DeviceTrustRoutePolicy::new(
        Action::Admin,
        ResourceRef::new("guardian-vault").with_id("vault-1"),
        requirement,
    )
}

#[test]
fn high_trust_route_denies_software_bound_device() {
    let decision = software_decision();
    let mtls = mtls_identity("serial-a", "fp-a", true);
    let context = DeviceTrustContext::new(decision.clone(), mtls.clone())
        .with_bound_user_session(bound_session(&mtls, decision.tier()));

    let actual = policy(DeviceTrustRequirement::hardware_backed()).evaluate(Some(&context));

    assert_eq!(
        actual,
        Decision::Deny {
            reason: DenyReason::DeviceTrustTierTooLow
        }
    );
}

#[test]
fn high_trust_route_allows_hardware_bound_session() {
    let decision = hardware_decision();
    let mtls = mtls_identity("serial-a", "fp-a", true);
    let context = DeviceTrustContext::new(decision.clone(), mtls.clone())
        .with_bound_user_session(bound_session(&mtls, decision.tier()));

    let actual = policy(DeviceTrustRequirement::hardware_backed()).evaluate(Some(&context));

    assert_eq!(
        actual,
        Decision::Allow {
            obligations: vec!["device-trust:hardware-backed".to_owned()]
        }
    );
}

#[test]
fn low_trust_route_allows_ci_only_in_test_profile() {
    let decision = ci_decision();
    let mtls = mtls_identity("serial-ci", "fp-ci", true);
    let context = DeviceTrustContext::new(decision.clone(), mtls.clone())
        .with_bound_user_session(bound_session(&mtls, decision.tier()))
        .with_profile(DeviceTrustProfile::Test);

    let actual =
        policy(DeviceTrustRequirement::software_bound_test_only()).evaluate(Some(&context));

    assert_eq!(
        actual,
        Decision::Allow {
            obligations: vec!["device-trust:software-bound".to_owned()]
        }
    );
}

#[test]
fn low_trust_route_denies_ci_identity_in_production_profile() {
    let decision = ci_decision();
    let mtls = mtls_identity("serial-ci", "fp-ci", true);
    let context = DeviceTrustContext::new(decision.clone(), mtls.clone())
        .with_bound_user_session(bound_session(&mtls, decision.tier()))
        .with_profile(DeviceTrustProfile::Production);

    let actual =
        policy(DeviceTrustRequirement::software_bound_test_only()).evaluate(Some(&context));

    assert_eq!(
        actual,
        Decision::Deny {
            reason: DenyReason::TestTrustProfileRequired
        }
    );
}

#[test]
fn revoked_device_trust_context_denies_before_route_policy() {
    let decision = hardware_decision();
    let mtls = mtls_identity("serial-a", "fp-a", true);
    let context = DeviceTrustContext::new(decision.clone(), mtls.clone())
        .with_bound_user_session(bound_session(&mtls, decision.tier()))
        .with_revoked_session(true);

    let actual = policy(DeviceTrustRequirement::hardware_backed()).evaluate(Some(&context));

    assert_eq!(
        actual,
        Decision::Deny {
            reason: DenyReason::DeviceTrustRevoked
        }
    );
}

#[test]
fn untrusted_edge_metadata_is_rejected_as_header_spoofing() {
    let decision = hardware_decision();
    let mtls = mtls_identity("serial-a", "fp-a", false);
    let context = DeviceTrustContext::new(decision.clone(), mtls.clone())
        .with_bound_user_session(bound_session(&mtls, decision.tier()));

    let actual = policy(DeviceTrustRequirement::hardware_backed()).evaluate(Some(&context));

    assert_eq!(
        actual,
        Decision::Deny {
            reason: DenyReason::UntrustedDeviceMetadata
        }
    );
}

#[test]
fn mismatched_bound_user_session_is_rejected() {
    let decision = hardware_decision();
    let mtls = mtls_identity("serial-a", "fp-a", true);
    let other_mtls = mtls_identity("serial-b", "fp-b", true);
    let context = DeviceTrustContext::new(decision.clone(), mtls)
        .with_bound_user_session(bound_session(&other_mtls, decision.tier()));

    let actual = policy(DeviceTrustRequirement::hardware_backed()).evaluate(Some(&context));

    assert_eq!(
        actual,
        Decision::Deny {
            reason: DenyReason::DeviceSessionBindingMismatch
        }
    );
}

#[cfg(feature = "actix-web")]
mod actix_adapter {
    use super::*;
    use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
    use actix_web::{http::StatusCode, test, web, App, Error, HttpMessage, HttpResponse};
    use secure_authz::actix::DeviceTrustTransform;
    use std::future::{ready, Future, Ready};
    use std::pin::Pin;

    #[derive(Clone, Default)]
    struct Context {
        device_trust: Option<DeviceTrustContext>,
    }

    impl<S, B> Transform<S, ServiceRequest> for Context
    where
        S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
        S::Future: 'static,
        B: 'static,
    {
        type Response = ServiceResponse<B>;
        type Error = Error;
        type Transform = Middleware<S>;
        type InitError = ();
        type Future = Ready<Result<Self::Transform, Self::InitError>>;

        fn new_transform(&self, service: S) -> Self::Future {
            ready(Ok(Middleware {
                service,
                ctx: self.clone(),
            }))
        }
    }

    struct Middleware<S> {
        service: S,
        ctx: Context,
    }

    impl<S, B> Service<ServiceRequest> for Middleware<S>
    where
        S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
        S::Future: 'static,
        B: 'static,
    {
        type Response = ServiceResponse<B>;
        type Error = Error;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

        forward_ready!(service);

        fn call(&self, req: ServiceRequest) -> Self::Future {
            if let Some(context) = &self.ctx.device_trust {
                req.extensions_mut().insert(context.clone());
            }
            Box::pin(self.service.call(req))
        }
    }

    async fn inner() -> HttpResponse {
        HttpResponse::Ok().body("ok")
    }

    fn hardware_context(trusted_edge: bool) -> DeviceTrustContext {
        let decision = hardware_decision();
        let mtls = mtls_identity("serial-a", "fp-a", trusted_edge);
        DeviceTrustContext::new(decision.clone(), mtls.clone())
            .with_bound_user_session(bound_session(&mtls, decision.tier()))
    }

    #[actix_web::test]
    async fn actix_device_trust_transform_allows_trusted_context() {
        let srv = test::init_service(
            App::new()
                .wrap(DeviceTrustTransform::new(policy(
                    DeviceTrustRequirement::hardware_backed(),
                )))
                .wrap(Context {
                    device_trust: Some(hardware_context(true)),
                })
                .route("/", web::get().to(inner)),
        )
        .await;

        let resp = test::call_service(&srv, test::TestRequest::get().uri("/").to_request()).await;

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn actix_device_trust_transform_denies_missing_context() {
        let srv = test::init_service(
            App::new()
                .wrap(DeviceTrustTransform::new(policy(
                    DeviceTrustRequirement::hardware_backed(),
                )))
                .wrap(Context::default())
                .route("/", web::get().to(inner)),
        )
        .await;

        let resp = test::call_service(&srv, test::TestRequest::get().uri("/").to_request()).await;

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[actix_web::test]
    async fn actix_device_trust_transform_denies_untrusted_edge_context() {
        let srv = test::init_service(
            App::new()
                .wrap(DeviceTrustTransform::new(policy(
                    DeviceTrustRequirement::hardware_backed(),
                )))
                .wrap(Context {
                    device_trust: Some(hardware_context(false)),
                })
                .route("/", web::get().to(inner)),
        )
        .await;

        let resp = test::call_service(&srv, test::TestRequest::get().uri("/").to_request()).await;

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
