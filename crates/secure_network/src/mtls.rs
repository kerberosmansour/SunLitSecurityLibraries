//! mTLS client identity validation extracted from trusted edge metadata.

use time::OffsetDateTime;

/// Client certificate identity accepted from a trusted mTLS edge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MtlsClientIdentity {
    /// Certificate serial.
    pub serial: String,
    /// Certificate fingerprint.
    pub fingerprint: String,
    /// Certificate validity start.
    pub not_before: OffsetDateTime,
    /// Certificate expiry.
    pub not_after: OffsetDateTime,
    /// Whether this identity was extracted by a trusted edge component.
    pub trusted_edge: bool,
}

impl MtlsClientIdentity {
    /// Creates a new mTLS client identity.
    #[must_use]
    pub fn new(
        serial: impl Into<String>,
        fingerprint: impl Into<String>,
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
        trusted_edge: bool,
    ) -> Self {
        Self {
            serial: serial.into(),
            fingerprint: fingerprint.into(),
            not_before,
            not_after,
            trusted_edge,
        }
    }

    /// Validates certificate time bounds and revocation status.
    #[must_use]
    pub fn validate_at(
        &self,
        now: OffsetDateTime,
        revocation: &dyn MtlsRevocationLookup,
    ) -> MtlsClientIdentityStatus {
        if !self.trusted_edge {
            return MtlsClientIdentityStatus::UntrustedEdge;
        }
        if revocation.is_revoked(&self.serial, &self.fingerprint) {
            return MtlsClientIdentityStatus::Revoked;
        }
        if now < self.not_before {
            return MtlsClientIdentityStatus::NotYetValid;
        }
        if now >= self.not_after {
            return MtlsClientIdentityStatus::Expired;
        }
        MtlsClientIdentityStatus::Valid
    }
}

/// Status of an extracted mTLS client identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MtlsClientIdentityStatus {
    /// Identity is currently valid.
    Valid,
    /// Identity came from an untrusted edge/header source.
    UntrustedEdge,
    /// Certificate is not valid yet.
    NotYetValid,
    /// Certificate is expired.
    Expired,
    /// Certificate is revoked.
    Revoked,
}

/// Revocation lookup for mTLS certificate identities.
pub trait MtlsRevocationLookup {
    /// Returns true when the certificate serial/fingerprint is revoked.
    fn is_revoked(&self, serial: &str, fingerprint: &str) -> bool;
}

/// Revocation lookup that treats every identity as active.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoMtlsRevocations;

impl MtlsRevocationLookup for NoMtlsRevocations {
    fn is_revoked(&self, _serial: &str, _fingerprint: &str) -> bool {
        false
    }
}
