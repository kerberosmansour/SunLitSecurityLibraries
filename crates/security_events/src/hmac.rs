//! Per-event HMAC signing for tamper-evident security logs.

use crate::event::{EventOutcome, EventValue, SecurityEvent};
use crate::kind::EventKind;
use hmac::{Hmac, Mac};
use security_core::severity::SecuritySeverity;
use security_core::types::{RequestId, TenantId, TraceId};
use serde::Serialize;
use std::collections::BTreeMap;
use std::net::IpAddr;
use time::OffsetDateTime;
use uuid::Uuid;

type HmacSha256 = Hmac<sha2::Sha256>;

/// Errors returned by [`HmacEventSigner`].
#[derive(Debug)]
#[non_exhaustive]
pub enum HmacError {
    /// The HMAC key was empty.
    MissingHmacKey,
    /// The event did not carry a signature to verify.
    MissingHmac,
    /// The event could not be serialized consistently for signing.
    Serialization(serde_json::Error),
    /// The stored hex signature could not be decoded.
    InvalidSignatureEncoding(hex::FromHexError),
}

impl std::fmt::Display for HmacError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingHmacKey => write!(f, "missing_hmac_key"),
            Self::MissingHmac => write!(f, "missing_hmac"),
            Self::Serialization(error) => write!(f, "failed to serialize event for HMAC: {error}"),
            Self::InvalidSignatureEncoding(error) => {
                write!(f, "invalid HMAC encoding: {error}")
            }
        }
    }
}

impl std::error::Error for HmacError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MissingHmacKey | Self::MissingHmac => None,
            Self::Serialization(error) => Some(error),
            Self::InvalidSignatureEncoding(error) => Some(error),
        }
    }
}

impl From<serde_json::Error> for HmacError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization(error)
    }
}

impl From<hex::FromHexError> for HmacError {
    fn from(error: hex::FromHexError) -> Self {
        Self::InvalidSignatureEncoding(error)
    }
}

#[derive(Clone)]
struct HmacKey {
    bytes: Vec<u8>,
}

impl HmacKey {
    fn new(key: impl AsRef<str>) -> Result<Self, HmacError> {
        let bytes = key.as_ref().as_bytes().to_vec();
        if bytes.is_empty() {
            return Err(HmacError::MissingHmacKey);
        }

        Ok(Self { bytes })
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for HmacKey {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

/// Signs and verifies [`SecurityEvent`] values with HMAC-SHA256.
///
/// The signing key is kept in a redacted local wrapper that clears its memory on
/// drop. When integrating with `secure_data`, callers can source the secret from
/// `SecretString::expose_secret()` at the boundary to avoid a crate cycle.
pub struct HmacEventSigner {
    key: HmacKey,
}

impl std::fmt::Debug for HmacEventSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HmacEventSigner([REDACTED])")
    }
}

impl HmacEventSigner {
    /// Creates a new signer from secret HMAC key material.
    ///
    /// # Errors
    ///
    /// Returns [`HmacError::MissingHmacKey`] if the key is empty.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use security_events::hmac::HmacEventSigner;
    ///
    /// let signer = HmacEventSigner::new("audit-key")?;
    /// # let _ = signer;
    /// # Ok::<(), security_events::hmac::HmacError>(())
    /// ```
    pub fn new(key: impl AsRef<str>) -> Result<Self, HmacError> {
        Ok(Self {
            key: HmacKey::new(key)?,
        })
    }

    /// Signs `event`, stores the signature in `event.hmac`, and returns it.
    ///
    /// # Errors
    ///
    /// Returns [`HmacError::Serialization`] if the event cannot be serialized.
    pub fn sign_event(&self, event: &mut SecurityEvent) -> Result<String, HmacError> {
        let signature = self.compute_signature(event)?;
        event.hmac = Some(signature.clone());
        Ok(signature)
    }

    /// Verifies the HMAC carried on `event`.
    ///
    /// # Errors
    ///
    /// Returns [`HmacError::MissingHmac`] if the event has not been signed.
    /// Returns [`HmacError::Serialization`] if the event cannot be serialized.
    /// Returns [`HmacError::InvalidSignatureEncoding`] if the stored signature is not valid hex.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use security_core::severity::SecuritySeverity;
    /// use security_events::event::{EventOutcome, SecurityEvent};
    /// use security_events::hmac::HmacEventSigner;
    /// use security_events::kind::EventKind;
    ///
    /// let signer = HmacEventSigner::new("audit-key")?;
    /// let mut event = SecurityEvent::new(
    ///     EventKind::AdminAction,
    ///     SecuritySeverity::Info,
    ///     EventOutcome::Success,
    /// );
    /// signer.sign_event(&mut event)?;
    /// assert!(signer.verify_event(&event)?);
    /// # Ok::<(), security_events::hmac::HmacError>(())
    /// ```
    pub fn verify_event(&self, event: &SecurityEvent) -> Result<bool, HmacError> {
        let provided = event.hmac.as_deref().ok_or(HmacError::MissingHmac)?;
        let provided = hex::decode(provided)?;
        let payload = canonical_event_json(event)?;
        let mut mac = self.new_mac();
        mac.update(&payload);
        Ok(mac.verify_slice(&provided).is_ok())
    }

    fn compute_signature(&self, event: &SecurityEvent) -> Result<String, HmacError> {
        let payload = canonical_event_json(event)?;
        let mut mac = self.new_mac();
        mac.update(&payload);
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    fn new_mac(&self) -> HmacSha256 {
        HmacSha256::new_from_slice(self.key.as_bytes())
            .expect("HMAC key was validated as non-empty")
    }
}

#[derive(Serialize)]
struct SignableSecurityEvent<'a> {
    timestamp: &'a OffsetDateTime,
    event_id: &'a Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_event_id: &'a Option<Uuid>,
    kind: &'a EventKind,
    severity: &'a SecuritySeverity,
    outcome: &'a EventOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant: &'a Option<TenantId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_ip: &'a Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: &'a Option<RequestId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trace_id: &'a Option<TraceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_code: &'a Option<&'static str>,
    labels: &'a BTreeMap<String, EventValue>,
}

fn canonical_event_json(event: &SecurityEvent) -> Result<Vec<u8>, HmacError> {
    Ok(serde_json::to_vec(&SignableSecurityEvent {
        timestamp: &event.timestamp,
        event_id: &event.event_id,
        parent_event_id: &event.parent_event_id,
        kind: &event.kind,
        severity: &event.severity,
        outcome: &event.outcome,
        actor: &event.actor,
        tenant: &event.tenant,
        source_ip: &event.source_ip,
        request_id: &event.request_id,
        trace_id: &event.trace_id,
        session_id: &event.session_id,
        resource: &event.resource,
        reason_code: &event.reason_code,
        labels: &event.labels,
    })?)
}
