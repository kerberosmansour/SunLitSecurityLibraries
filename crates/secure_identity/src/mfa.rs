//! MFA challenge and provider types (stub).

use crate::error::IdentityError;

/// An MFA challenge issued to an actor.
pub struct MfaChallenge {
    /// Unique identifier for this challenge.
    pub challenge_id: String,
    /// The kind of MFA challenge.
    pub kind: MfaChallengeKind,
}

/// The kind of MFA challenge.
pub enum MfaChallengeKind {
    /// A time-based one-time password challenge.
    Totp,
}

/// A response to an MFA challenge.
pub struct MfaResponse {
    /// The ID of the challenge being responded to.
    pub challenge_id: String,
    /// The one-time code provided by the actor.
    pub code: String,
}

/// A trait for MFA providers.
#[allow(async_fn_in_trait)]
pub trait MfaProvider {
    /// Issues an MFA challenge to the given actor.
    async fn issue_challenge(&self, actor_id: &str) -> Result<MfaChallenge, IdentityError>;

    /// Verifies an MFA response, returning `true` if the response is valid.
    async fn verify_response(&self, response: &MfaResponse) -> Result<bool, IdentityError>;
}
