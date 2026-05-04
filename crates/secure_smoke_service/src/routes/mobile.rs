//! Mobile security smoke routes (Milestone 8).
//!
//! Each route exercises a single MASVS mobile security control via the
//! `secure_network`, `secure_resilience`, `secure_privacy`, `secure_data`,
//! `secure_identity`, and `secure_boundary` crates.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use std::time::Duration;

use security_events::sink::InMemorySink;

// ── Request/Response DTOs ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct TlsVersionRequest {
    pub version: String,
}

#[derive(Debug, Deserialize)]
pub struct CertPinRequest {
    pub cert_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct CleartextRequest {
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct StoragePolicyRequest {
    pub classification: String,
    #[serde(default)]
    pub is_encrypted: bool,
    #[serde(default)]
    pub has_hardware_keystore: bool,
}

#[derive(Debug, Deserialize)]
pub struct SensitiveBufferRequest {
    pub secret: String,
}

#[derive(Debug, Deserialize)]
pub struct BiometricRequest {
    pub biometric_class: u8,
    #[serde(default)]
    pub crypto_binding: Option<CryptoBindingDto>,
    #[serde(default)]
    pub device_credential_fallback: bool,
    pub current_enrollment_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CryptoBindingDto {
    pub key_id: String,
    pub enrollment_id: String,
}

#[derive(Debug, Deserialize)]
pub struct StepUpRequest {
    pub operation: String,
    pub last_auth_age_secs: u64,
}

#[derive(Debug, Deserialize)]
pub struct DeepLinkRequest {
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct WebViewUrlRequest {
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct ClipboardRequest {
    pub classification: String,
}

#[derive(Debug, Deserialize)]
pub struct RootDetectRequest {
    pub signal_type: String,
    #[serde(default = "default_confidence")]
    pub confidence: String,
    #[serde(default)]
    pub evidence: String,
}

fn default_confidence() -> String {
    "high".to_string()
}

#[derive(Debug, Deserialize)]
pub struct AppIntegrityRequest {
    pub expected_hash: String,
    pub actual_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct PiiClassifyRequest {
    pub data: String,
}

#[derive(Debug, Deserialize)]
pub struct PseudonymizeRequest {
    pub data: String,
    #[serde(default = "default_salt")]
    pub salt: String,
}

fn default_salt() -> String {
    "smoke-test-salt-value".to_string()
}

#[derive(Debug, Deserialize)]
pub struct ConsentRequest {
    pub purpose: String,
    #[serde(default = "default_consent_state")]
    pub consent_state: String,
    pub requested_purpose: String,
}

fn default_consent_state() -> String {
    "granted".to_string()
}

// ── Helper: parse TLS version string ────────────────────────────────────

fn parse_tls_version(s: &str) -> Option<secure_network::TlsVersion> {
    match s.to_uppercase().replace(['.', ' '], "").as_str() {
        "SSL3" | "SSL30" | "SSLV3" => Some(secure_network::TlsVersion::Ssl3),
        "TLS1" | "TLS10" | "TLSV1" | "TLSV10" => Some(secure_network::TlsVersion::Tls10),
        "TLS11" | "TLSV11" => Some(secure_network::TlsVersion::Tls11),
        "TLS12" | "TLSV12" => Some(secure_network::TlsVersion::Tls12),
        "TLS13" | "TLSV13" => Some(secure_network::TlsVersion::Tls13),
        _ => None,
    }
}

// ── Helper: parse DataClassification ────────────────────────────────────

fn parse_classification(s: &str) -> Option<security_core::classification::DataClassification> {
    use security_core::classification::DataClassification;
    match s.to_lowercase().as_str() {
        "public" => Some(DataClassification::Public),
        "internal" => Some(DataClassification::Internal),
        "confidential" => Some(DataClassification::Confidential),
        "pii" => Some(DataClassification::PII),
        "regulated" => Some(DataClassification::Regulated),
        "credentials" => Some(DataClassification::Credentials),
        _ => None,
    }
}

// ── Route handlers ──────────────────────────────────────────────────────

/// POST `/smoke/mobile/tls-version` — TLS version validation.
pub async fn tls_version_check(axum::Json(req): axum::Json<TlsVersionRequest>) -> Response {
    let version = match parse_tls_version(&req.version) {
        Some(v) => v,
        None => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                serde_json::json!({
                    "code": "invalid_tls_version",
                    "message": "unrecognised TLS version string"
                })
                .to_string(),
            )
                .into_response();
        }
    };

    let policy = secure_network::TlsPolicy::new(secure_network::TlsVersion::Tls12);
    let result = policy.validate(version, &secure_network::CipherSuite::Aes256Gcm);

    match result {
        secure_network::TlsValidationResult::Allow => (
            StatusCode::OK,
            serde_json::json!({
                "code": "tls_version_accepted",
                "version": format!("{version:?}")
            })
            .to_string(),
        )
            .into_response(),
        secure_network::TlsValidationResult::Deny { reason } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            serde_json::json!({
                "code": "tls_version_rejected",
                "reason": format!("{reason:?}")
            })
            .to_string(),
        )
            .into_response(),
    }
}

/// POST `/smoke/mobile/cert-pin` — Certificate pin verification.
pub async fn cert_pin_check(axum::Json(req): axum::Json<CertPinRequest>) -> Response {
    let pin_set = match secure_network::PinSet::from_hex_hashes(&[req.cert_hash.as_str()]) {
        Ok(ps) => ps,
        Err(_) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                serde_json::json!({
                    "code": "invalid_hash",
                    "message": "cert_hash must be a 64-char hex SHA-256"
                })
                .to_string(),
            )
                .into_response();
        }
    };

    // Parse the hex hash into bytes for direct pin-set matching.
    let spki_hash = match hex_to_32_bytes(&req.cert_hash) {
        Some(h) => h,
        None => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                serde_json::json!({ "code": "invalid_hash" }).to_string(),
            )
                .into_response();
        }
    };

    // `PinSet::matches` is the core pin check. In a real app `validate_der`
    // would hash the certificate SPKI and call `matches` internally.
    if pin_set.matches(&spki_hash) {
        (
            StatusCode::OK,
            serde_json::json!({ "code": "pin_valid" }).to_string(),
        )
            .into_response()
    } else {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            serde_json::json!({ "code": "pin_mismatch" }).to_string(),
        )
            .into_response()
    }
}

fn hex_to_32_bytes(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).ok()?;
        out[i] = u8::from_str_radix(s, 16).ok()?;
    }
    Some(out)
}

/// POST `/smoke/mobile/cleartext` — Cleartext traffic detection.
pub async fn cleartext_check(axum::Json(req): axum::Json<CleartextRequest>) -> Response {
    let detector = secure_network::CleartextDetector::new();
    let result = detector.check(&req.url);

    match result {
        secure_network::CleartextResult::Secure => (
            StatusCode::OK,
            serde_json::json!({ "code": "secure", "url": req.url }).to_string(),
        )
            .into_response(),
        secure_network::CleartextResult::ExemptedLocalhost => (
            StatusCode::OK,
            serde_json::json!({ "code": "exempted_localhost", "url": req.url }).to_string(),
        )
            .into_response(),
        other => (
            StatusCode::UNPROCESSABLE_ENTITY,
            serde_json::json!({
                "code": "cleartext_blocked",
                "detail": format!("{other:?}")
            })
            .to_string(),
        )
            .into_response(),
    }
}

/// POST `/smoke/mobile/storage-policy` — Mobile storage policy enforcement.
pub async fn storage_policy_check(axum::Json(req): axum::Json<StoragePolicyRequest>) -> Response {
    let classification = match parse_classification(&req.classification) {
        Some(c) => c,
        None => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                serde_json::json!({ "code": "invalid_classification" }).to_string(),
            )
                .into_response();
        }
    };

    let policy =
        secure_data::mobile_storage::MobileStoragePolicy::for_classification(classification);
    let violations = policy.check_compliance(req.is_encrypted, req.has_hardware_keystore);

    if violations.is_empty() {
        (
            StatusCode::OK,
            serde_json::json!({
                "code": "compliant",
                "requires_encryption": policy.requires_encryption(),
                "requires_hardware_keystore": policy.requires_hardware_keystore()
            })
            .to_string(),
        )
            .into_response()
    } else {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            serde_json::json!({
                "code": "non_compliant",
                "violation_count": violations.len(),
                "requires_encryption": policy.requires_encryption(),
                "requires_hardware_keystore": policy.requires_hardware_keystore()
            })
            .to_string(),
        )
            .into_response()
    }
}

/// POST `/smoke/mobile/sensitive-buffer` — Sensitive buffer handling.
pub async fn sensitive_buffer_check(
    axum::Json(req): axum::Json<SensitiveBufferRequest>,
) -> Response {
    let mut buf = secure_data::mobile_storage::SensitiveBuffer::new(req.secret.into_bytes());
    let debug_repr = format!("{buf:?}");
    buf.wipe();
    let after_wipe = buf.expose().to_vec();

    // The response must NOT contain the original secret.
    (
        StatusCode::OK,
        serde_json::json!({
            "code": "buffer_handled",
            "debug_contains_secret": debug_repr.contains("REDACTED"),
            "wiped_length": after_wipe.len(),
            "wiped_all_zeroes": after_wipe.iter().all(|&b| b == 0)
        })
        .to_string(),
    )
        .into_response()
}

/// POST `/smoke/mobile/biometric` — Biometric result validation.
pub async fn biometric_check(axum::Json(req): axum::Json<BiometricRequest>) -> Response {
    let biometric_class = match req.biometric_class {
        1 => secure_identity::biometric::BiometricClass::Class1,
        2 => secure_identity::biometric::BiometricClass::Class2,
        3 => secure_identity::biometric::BiometricClass::Class3,
        _ => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                serde_json::json!({ "code": "invalid_biometric_class" }).to_string(),
            )
                .into_response();
        }
    };

    let crypto_binding = req
        .crypto_binding
        .map(|cb| secure_identity::biometric::CryptoBinding {
            key_id: cb.key_id,
            enrollment_id: cb.enrollment_id,
        });

    let bio_result = secure_identity::biometric::BiometricAuthResult {
        biometric_class,
        crypto_binding,
        device_credential_fallback: req.device_credential_fallback,
    };

    let policy = secure_identity::biometric::BiometricPolicy::default();
    let current_eid = req.current_enrollment_id.as_deref();
    let validation = policy.validate(&bio_result, current_eid);

    match validation {
        secure_identity::biometric::BiometricValidation::Accepted => (
            StatusCode::OK,
            serde_json::json!({ "code": "biometric_accepted" }).to_string(),
        )
            .into_response(),
        secure_identity::biometric::BiometricValidation::Rejected(reason) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            serde_json::json!({
                "code": "biometric_rejected",
                "reason": format!("{reason:?}")
            })
            .to_string(),
        )
            .into_response(),
    }
}

/// POST `/smoke/mobile/step-up` — Step-up authentication enforcement.
pub async fn step_up_check(axum::Json(req): axum::Json<StepUpRequest>) -> Response {
    let policy = secure_identity::step_up::StepUpPolicy::new(
        req.operation.clone(),
        Duration::from_secs(300), // 5-minute max auth age
    );
    let decision = policy.evaluate(Duration::from_secs(req.last_auth_age_secs));

    match decision {
        secure_identity::step_up::StepUpDecision::Required => (
            StatusCode::UNPROCESSABLE_ENTITY,
            serde_json::json!({
                "code": "step_up_required",
                "operation": req.operation
            })
            .to_string(),
        )
            .into_response(),
        secure_identity::step_up::StepUpDecision::NotRequired => (
            StatusCode::OK,
            serde_json::json!({
                "code": "step_up_not_required",
                "operation": req.operation
            })
            .to_string(),
        )
            .into_response(),
    }
}

/// POST `/smoke/mobile/deep-link` — Deep link URL validation.
pub async fn deep_link_check(axum::Json(req): axum::Json<DeepLinkRequest>) -> Response {
    let validator = secure_boundary::platform::DeepLinkValidator::new(&["myapp", "https"]);
    let result = validator.validate(&req.url);

    match result {
        Ok(safe) => (
            StatusCode::OK,
            serde_json::json!({
                "code": "valid_deep_link",
                "url": safe.as_inner()
            })
            .to_string(),
        )
            .into_response(),
        Err(rejection) => {
            let code = match rejection {
                secure_boundary::platform::PlatformRejection::DangerousScheme => "dangerous_scheme",
                secure_boundary::platform::PlatformRejection::InvalidScheme => "invalid_scheme",
                secure_boundary::platform::PlatformRejection::PathTraversal => "path_traversal",
                secure_boundary::platform::PlatformRejection::MalformedUrl => "malformed_url",
                _ => "rejected",
            };
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                serde_json::json!({
                    "code": code,
                    "detail": format!("{rejection:?}")
                })
                .to_string(),
            )
                .into_response()
        }
    }
}

/// POST `/smoke/mobile/webview-url` — WebView URL safety check.
pub async fn webview_url_check(axum::Json(req): axum::Json<WebViewUrlRequest>) -> Response {
    let validator = secure_boundary::platform::WebViewUrlValidator::new()
        .with_allowed_domains(&["example.com", "safe.example.org"]);
    let result = validator.validate(&req.url);

    match result {
        Ok(safe) => (
            StatusCode::OK,
            serde_json::json!({
                "code": "webview_url_safe",
                "url": safe.as_inner()
            })
            .to_string(),
        )
            .into_response(),
        Err(rejection) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            serde_json::json!({
                "code": "webview_url_blocked",
                "detail": format!("{rejection:?}")
            })
            .to_string(),
        )
            .into_response(),
    }
}

/// POST `/smoke/mobile/clipboard` — Clipboard security policy check.
pub async fn clipboard_check(axum::Json(req): axum::Json<ClipboardRequest>) -> Response {
    let classification = match parse_classification(&req.classification) {
        Some(c) => c,
        None => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                serde_json::json!({ "code": "invalid_classification" }).to_string(),
            )
                .into_response();
        }
    };

    let policy = secure_boundary::platform::ClipboardPolicy::for_classification(classification);
    (
        StatusCode::OK,
        serde_json::json!({
            "code": "clipboard_policy_evaluated",
            "restrict_to_local_device": policy.restrict_to_local_device(),
            "expiration_seconds": policy.expiration_seconds()
        })
        .to_string(),
    )
        .into_response()
}

/// POST `/smoke/mobile/root-detect` — Environment detection signal processing.
pub async fn root_detect_check(axum::Json(req): axum::Json<RootDetectRequest>) -> Response {
    let confidence = match req.confidence.to_lowercase().as_str() {
        "low" => secure_resilience::Confidence::Low,
        "medium" => secure_resilience::Confidence::Medium,
        _ => secure_resilience::Confidence::High,
    };

    let signal = match req.signal_type.to_lowercase().as_str() {
        "root" => secure_resilience::EnvironmentSignal::RootDetected {
            confidence,
            evidence: req.evidence.clone(),
        },
        "emulator" => secure_resilience::EnvironmentSignal::EmulatorDetected {
            confidence,
            evidence: req.evidence.clone(),
        },
        "debugger" => secure_resilience::EnvironmentSignal::DebuggerAttached {
            confidence,
            evidence: req.evidence.clone(),
        },
        _ => secure_resilience::EnvironmentSignal::Unknown {
            label: req.signal_type.clone(),
            evidence: req.evidence.clone(),
        },
    };

    let sink = InMemorySink::new();
    let engine = secure_resilience::RaspEngine::new(secure_resilience::RaspPolicy::default());
    let decision = engine.process_signal(&signal, &sink);

    let decision_code = match &decision {
        secure_resilience::RaspDecision::Allow => "allow",
        secure_resilience::RaspDecision::Warn { .. } => "warn",
        secure_resilience::RaspDecision::Block { .. } => "block",
        secure_resilience::RaspDecision::Degrade { .. } => "degrade",
    };

    (
        StatusCode::OK,
        serde_json::json!({
            "code": "rasp_decision",
            "decision": decision_code,
            "detail": format!("{decision:?}"),
            "events_emitted": sink.events().len()
        })
        .to_string(),
    )
        .into_response()
}

/// POST `/smoke/mobile/app-integrity` — App integrity verification.
pub async fn app_integrity_check(axum::Json(req): axum::Json<AppIntegrityRequest>) -> Response {
    let sink = InMemorySink::new();
    let check = secure_resilience::IntegrityCheck::new_signature(&req.expected_hash);
    let result = check.verify_with_events(&req.actual_hash, &sink);

    match result {
        secure_resilience::IntegrityResult::Valid => (
            StatusCode::OK,
            serde_json::json!({
                "code": "integrity_valid",
                "events_emitted": sink.events().len()
            })
            .to_string(),
        )
            .into_response(),
        other => (
            StatusCode::UNPROCESSABLE_ENTITY,
            serde_json::json!({
                "code": "integrity_failed",
                "detail": format!("{other:?}"),
                "events_emitted": sink.events().len()
            })
            .to_string(),
        )
            .into_response(),
    }
}

/// POST `/smoke/mobile/pii-classify` — PII classification.
pub async fn pii_classify_check(axum::Json(req): axum::Json<PiiClassifyRequest>) -> Response {
    let classifier = secure_privacy::PiiClassifier::new();
    let classification = classifier.classify(&req.data);

    let label = match &classification {
        secure_privacy::PiiClassification::Email => "email",
        secure_privacy::PiiClassification::PhoneNumber => "phone_number",
        secure_privacy::PiiClassification::IpAddress => "ip_address",
        secure_privacy::PiiClassification::DeviceIdentifier => "device_identifier",
        secure_privacy::PiiClassification::Custom(name) => name.as_str(),
        secure_privacy::PiiClassification::None => "none",
        _ => "unknown",
    };

    (
        StatusCode::OK,
        serde_json::json!({
            "code": "pii_classified",
            "classification": label
        })
        .to_string(),
    )
        .into_response()
}

/// POST `/smoke/mobile/pseudonymize` — Data pseudonymization.
pub async fn pseudonymize_check(axum::Json(req): axum::Json<PseudonymizeRequest>) -> Response {
    let pseudonymizer = match secure_privacy::Pseudonymizer::new(req.salt.as_bytes()) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({
                    "code": "pseudonymizer_error",
                    "detail": format!("{e:?}")
                })
                .to_string(),
            )
                .into_response();
        }
    };

    let result = pseudonymizer.pseudonymize(&req.data);

    (
        StatusCode::OK,
        serde_json::json!({
            "code": "pseudonymized",
            "value": result.value
        })
        .to_string(),
    )
        .into_response()
}

/// POST `/smoke/mobile/consent` — Consent policy enforcement.
pub async fn consent_check(axum::Json(req): axum::Json<ConsentRequest>) -> Response {
    let purpose = secure_privacy::ConsentPurpose::new(&req.purpose);
    let mut policy = secure_privacy::ConsentPolicy::new(purpose);

    match req.consent_state.to_lowercase().as_str() {
        "granted" => policy.grant(),
        "denied" => policy.deny(),
        "withdrawn" => {
            policy.grant();
            policy.withdraw();
        }
        _ => {} // NotCollected — default state
    }

    let sink = InMemorySink::new();
    let requested = secure_privacy::ConsentPurpose::new(&req.requested_purpose);
    let decision = policy.check_consent(&requested, &sink);

    let code = match decision {
        secure_privacy::ConsentDecision::Allowed => "consent_allowed",
        secure_privacy::ConsentDecision::Denied => "consent_denied",
        secure_privacy::ConsentDecision::NotCollected => "consent_not_collected",
        secure_privacy::ConsentDecision::Withdrawn => "consent_withdrawn",
        secure_privacy::ConsentDecision::PurposeMismatch => "consent_purpose_mismatch",
        _ => "consent_unknown",
    };

    (
        if code == "consent_allowed" {
            StatusCode::OK
        } else {
            StatusCode::UNPROCESSABLE_ENTITY
        },
        serde_json::json!({
            "code": code,
            "events_emitted": sink.events().len()
        })
        .to_string(),
    )
        .into_response()
}
