use secure_network::{
    MtlsClientIdentity, MtlsClientIdentityStatus, MtlsRevocationLookup, NoMtlsRevocations,
};
use time::{Duration, OffsetDateTime};

#[derive(Clone, Debug)]
struct Revoked;

impl MtlsRevocationLookup for Revoked {
    fn is_revoked(&self, serial: &str, fingerprint: &str) -> bool {
        serial == "serial-1" && fingerprint == "fingerprint-1"
    }
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_778_000_000).expect("valid fixture time")
}

fn identity(trusted_edge: bool) -> MtlsClientIdentity {
    MtlsClientIdentity::new(
        "serial-1",
        "fingerprint-1",
        now() - Duration::minutes(1),
        now() + Duration::days(1),
        trusted_edge,
    )
}

#[test]
fn trusted_edge_identity_within_validity_window_is_valid() {
    assert_eq!(
        identity(true).validate_at(now(), &NoMtlsRevocations),
        MtlsClientIdentityStatus::Valid
    );
}

#[test]
fn untrusted_edge_identity_is_rejected_before_time_checks() {
    assert_eq!(
        identity(false).validate_at(now(), &NoMtlsRevocations),
        MtlsClientIdentityStatus::UntrustedEdge
    );
}

#[test]
fn revoked_identity_is_rejected() {
    assert_eq!(
        identity(true).validate_at(now(), &Revoked),
        MtlsClientIdentityStatus::Revoked
    );
}
