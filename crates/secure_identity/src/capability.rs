//! Strict single-use tenant+operation capability.
//!
//! A capability is a narrow, short-lived bearer statement: *this subject may
//! perform exactly this operation, for exactly this tenant, against exactly
//! this request, once, within at most 60 seconds*. It exists so a trusted
//! broker can act on behalf of a caller that holds **no** database credential
//! and **no** network path to the database.
//!
//! What makes it safe is what it refuses:
//!
//! * **RS256 only, by construction.** The token's own `alg` header is never
//!   honoured, so `alg: none` and HMAC key-confusion cannot apply.
//! * **Bounded lifetime, checked twice.** The issuer refuses to mint a
//!   capability longer than [`MAX_TTL_SECONDS`], and the verifier independently
//!   refuses one it receives — it does not assume a conforming issuer.
//! * **Single use.** The `jti` is consumed through a caller-supplied
//!   [`ReplayStore`] as part of verification, so replay and concurrent
//!   double-use fail closed rather than racing.
//! * **Request binding.** The capability commits to a length-framed SHA-256 of
//!   (tenant, operation, request body), so authority cannot be moved to a
//!   different statement.
//! * **Redaction.** `Debug` and error output carry no token, no request body,
//!   no `jti`, and no `subject` or `tenant`. `Operation` and `expires_at` are
//!   rendered, because they identify neither a principal nor data.
//!
//! # Examples
//!
//! ```no_run
//! use secure_identity::capability::{
//!     CapabilityIssuer, CapabilityRequest, CapabilityVerifier, Expected,
//!     InMemoryReplayStore, Operation, RsaCapabilitySigner,
//! };
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let signing_pem = std::fs::read("capability_signing_key.pem")?;
//! let verify_pem = std::fs::read("capability_public_key.pem")?;
//!
//! let request = CapabilityRequest::new("acct-42", Operation::Read, b"SELECT 1");
//!
//! let token = CapabilityIssuer::new(
//!     "https://auth.example.com".to_string(),
//!     "broker".to_string(),
//!     RsaCapabilitySigner::from_pkcs8_pem(&signing_pem)?,
//! )
//! .issue("svc-api", &request, 30)
//! .await?;
//!
//! let verifier = CapabilityVerifier::from_rsa_pem(
//!     "https://auth.example.com".to_string(),
//!     "broker".to_string(),
//!     &verify_pem,
//! )?;
//! let store = InMemoryReplayStore::default();
//! let expected = Expected::new("svc-api", "acct-42", Operation::Read, b"SELECT 1");
//!
//! let verified = verifier.verify(&token, &expected, &store).await?;
//! assert_eq!(verified.tenant(), "acct-42");
//!
//! // The same capability cannot be used twice.
//! assert!(verifier.verify(&token, &expected, &store).await.is_err());
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine as _;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use ring::rand::SystemRandom;
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
use serde::{Deserialize, Serialize};

/// The maximum lifetime a capability may carry, in seconds.
///
/// Enforced independently by the issuer and the verifier.
pub const MAX_TTL_SECONDS: u64 = 60;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// The closed set of operations a capability may authorise.
///
/// This is deliberately an enum rather than a free string: a broker must be
/// able to exhaustively match on what it is being asked to do, and an unknown
/// variant must fail to deserialise rather than being forwarded.
///
/// It is deliberately **not** `#[non_exhaustive]`. Marking it so would stop
/// downstream brokers writing an exhaustive `match`, which is precisely the
/// review property this type exists to give them: adding a variant here MUST
/// break every broker at compile time so each one re-decides what it authorises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// Read rows the tenant already owns.
    Read,
    /// Append new rows for the tenant.
    Append,
    /// Modify existing rows the tenant owns.
    Update,
    /// Remove rows the tenant owns.
    Delete,
    /// Compute an aggregate over the tenant's own rows.
    Aggregate,
}

impl Operation {
    /// A stable wire label, used in the framed request digest.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Append => "append",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Aggregate => "aggregate",
        }
    }
}

/// Errors returned when issuing or verifying a capability.
///
/// Every variant is deliberately free of token, claim and request material:
/// these values are logged, and a capability is bearer authority.
///
/// # Examples
///
/// ```
/// use secure_identity::capability::CapabilityError;
///
/// assert_eq!(CapabilityError::Replayed.to_string(), "capability already used");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CapabilityError {
    /// The token was not well-formed, or its signature did not verify.
    Malformed,
    /// The signature did not verify against the pinned public key.
    BadSignature,
    /// The `iss` claim did not match the configured issuer.
    IssuerMismatch,
    /// The `aud` claim did not match the configured audience.
    AudienceMismatch,
    /// The `sub` claim did not match the expected subject.
    SubjectMismatch,
    /// The tenant claim did not match the expected tenant.
    TenantMismatch,
    /// The operation claim did not match the expected operation.
    OperationMismatch,
    /// The request digest did not match the request being performed.
    RequestMismatch,
    /// The capability has expired.
    Expired,
    /// The capability is not valid yet.
    NotYetValid,
    /// The capability's lifetime exceeds [`MAX_TTL_SECONDS`].
    TtlTooLong,
    /// The capability carried no `jti`, so it cannot be made single-use.
    MissingJti,
    /// The capability has already been used.
    Replayed,
    /// The replay store could not be consulted at all. The capability was
    /// **not** consumed, so it may be retried.
    ReplayStoreUnavailable,
    /// The replay store was reached but its answer was lost — for example a
    /// distributed store that committed the claim and then failed to reply.
    ///
    /// The capability MUST be treated as **spent**. Retrying is unsafe: the
    /// claim may already have succeeded, and a caller that retries on this is
    /// building exactly the double-use the `jti` exists to prevent.
    ReplayIndeterminate,
    /// The supplied key material could not be parsed.
    InvalidKey,
    /// Signing failed.
    SigningFailed,
    /// The system clock is before the Unix epoch.
    ClockUnavailable,
}

impl std::fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::Malformed => "capability malformed",
            Self::BadSignature => "capability signature invalid",
            Self::IssuerMismatch => "capability issuer mismatch",
            Self::AudienceMismatch => "capability audience mismatch",
            Self::SubjectMismatch => "capability subject mismatch",
            Self::TenantMismatch => "capability tenant mismatch",
            Self::OperationMismatch => "capability operation mismatch",
            Self::RequestMismatch => "capability request binding mismatch",
            Self::Expired => "capability expired",
            Self::NotYetValid => "capability not yet valid",
            Self::TtlTooLong => "capability lifetime exceeds the permitted maximum",
            Self::MissingJti => "capability has no jti",
            Self::Replayed => "capability already used",
            Self::ReplayStoreUnavailable => "replay store unavailable",
            Self::ReplayIndeterminate => {
                "replay store outcome indeterminate; capability must be treated as spent"
            }
            Self::InvalidKey => "invalid key material",
            Self::SigningFailed => "capability signing failed",
            Self::ClockUnavailable => "system clock unavailable",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for CapabilityError {}

/// The exact request a capability is bound to.
///
/// The digest is length-framed, so field boundaries cannot be shifted:
/// `("ab", "c")` and `("a", "bc")` produce different digests.
#[derive(Clone)]
pub struct CapabilityRequest {
    tenant: String,
    operation: Operation,
    digest: [u8; 32],
}

impl CapabilityRequest {
    /// Binds a capability to a tenant, operation and exact request body.
    #[must_use]
    pub fn new(tenant: &str, operation: Operation, body: &[u8]) -> Self {
        Self {
            tenant: tenant.to_string(),
            operation,
            digest: framed_digest(tenant, operation, body),
        }
    }

    /// The tenant this request belongs to.
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// The operation being requested.
    #[must_use]
    pub const fn operation(&self) -> Operation {
        self.operation
    }

    /// The framed SHA-256 digest binding tenant, operation and body.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

impl std::fmt::Debug for CapabilityRequest {
    /// Renders without the request body or digest.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapabilityRequest")
            .field("tenant", &"<redacted>")
            .field("operation", &self.operation)
            .field("digest", &"<redacted>")
            .finish()
    }
}

/// What the verifier requires the capability to say.
#[derive(Clone)]
pub struct Expected {
    subject: String,
    request: CapabilityRequest,
}

impl Expected {
    /// Describes the subject, tenant, operation and body the caller is about to act on.
    #[must_use]
    pub fn new(subject: &str, tenant: &str, operation: Operation, body: &[u8]) -> Self {
        Self {
            subject: subject.to_string(),
            request: CapabilityRequest::new(tenant, operation, body),
        }
    }
}

impl std::fmt::Debug for Expected {
    /// Renders without subject or request material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Expected")
            .field("subject", &"<redacted>")
            .field("request", &self.request)
            .finish()
    }
}

/// Length-framed SHA-256 over (tenant, operation, body).
///
/// Each field is preceded by its big-endian u64 length, so no reassignment of
/// bytes between fields can produce the same digest.
fn framed_digest(tenant: &str, operation: Operation, body: &[u8]) -> [u8; 32] {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(b"sunlit-capability-v1");
    for part in [tenant.as_bytes(), operation.as_str().as_bytes(), body] {
        ctx.update(&(part.len() as u64).to_be_bytes());
        ctx.update(part);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

/// Signs capability tokens.
///
/// This is an abstraction rather than a key so that a KMS-backed signer — which
/// never exposes private material to this process — can be substituted for the
/// local implementation without changing callers.
#[allow(async_fn_in_trait)]
pub trait CapabilitySigner {
    /// Signs the JWS signing input with RSASSA-PKCS1-v1_5 over SHA-256.
    ///
    /// This is `async` because the intended production implementation is a
    /// remote KMS. A synchronous seam would force `block_on` inside a caller's
    /// async runtime, which stalls or deadlocks the executor.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityError::SigningFailed`] if the signature cannot be produced.
    async fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, CapabilityError>;
}

/// A local RSA signer, for tests and for deployments without a KMS.
pub struct RsaCapabilitySigner {
    key: RsaKeyPair,
    rng: SystemRandom,
}

impl RsaCapabilitySigner {
    /// Loads a PKCS#8 PEM private key.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityError::InvalidKey`] if the PEM cannot be parsed.
    pub fn from_pkcs8_pem(pem: &[u8]) -> Result<Self, CapabilityError> {
        let der = pem_body(pem).ok_or(CapabilityError::InvalidKey)?;
        let key = RsaKeyPair::from_pkcs8(&der).map_err(|_| CapabilityError::InvalidKey)?;
        let bits = key.public().modulus_len() * 8;
        if !(MIN_RSA_MODULUS_BITS..=MAX_RSA_MODULUS_BITS).contains(&bits) {
            return Err(CapabilityError::InvalidKey);
        }
        Ok(Self {
            key,
            rng: SystemRandom::new(),
        })
    }
}

impl std::fmt::Debug for RsaCapabilitySigner {
    /// Renders without key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RsaCapabilitySigner { key: <redacted> }")
    }
}

impl CapabilitySigner for RsaCapabilitySigner {
    async fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, CapabilityError> {
        let mut sig = vec![0u8; self.key.public().modulus_len()];
        self.key
            .sign(&RSA_PKCS1_SHA256, &self.rng, signing_input, &mut sig)
            .map_err(|_| CapabilityError::SigningFailed)?;
        Ok(sig)
    }
}

/// Minimum RSA modulus accepted, in bits. Below this the signature is not
/// meaningfully unforgeable.
pub const MIN_RSA_MODULUS_BITS: usize = 2048;
/// Maximum RSA modulus accepted, in bits. Above this verification cost becomes
/// an amplification surface for an attacker who chooses the key.
pub const MAX_RSA_MODULUS_BITS: usize = 4096;

/// Extracts the RSA modulus size, in bits, from an SPKI DER public key.
///
/// The verifier cannot ask `DecodingKey` how large its key is, so the bound is
/// enforced here instead. Without this the signer would reject a weak key while
/// the verifier quietly accepted one — the asymmetry an attacker picks.
fn spki_rsa_modulus_bits(der: &[u8]) -> Option<usize> {
    // SPKI: SEQUENCE { SEQUENCE { OID, NULL }, BIT STRING { SEQUENCE { INTEGER n, INTEGER e } } }
    fn read_len(b: &[u8], i: &mut usize) -> Option<usize> {
        let first = *b.get(*i)?;
        *i += 1;
        if first < 0x80 {
            return Some(first as usize);
        }
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for _ in 0..n {
            len = (len << 8) | *b.get(*i)? as usize;
            *i += 1;
        }
        Some(len)
    }
    fn expect(b: &[u8], i: &mut usize, tag: u8) -> Option<usize> {
        if *b.get(*i)? != tag {
            return None;
        }
        *i += 1;
        read_len(b, i)
    }

    let mut i = 0usize;
    expect(der, &mut i, 0x30)?; // outer SEQUENCE
    let alg_len = expect(der, &mut i, 0x30)?; // AlgorithmIdentifier
    i += alg_len;
    expect(der, &mut i, 0x03)?; // BIT STRING
    i += 1; // unused-bits octet
    expect(der, &mut i, 0x30)?; // RSAPublicKey SEQUENCE
    let n_len = expect(der, &mut i, 0x02)?; // INTEGER modulus
                                            // A leading 0x00 is DER sign padding, not key material.
    let leading_zero = usize::from(der.get(i) == Some(&0x00));
    Some((n_len - leading_zero) * 8)
}

/// Strips PEM armour and base64-decodes the body.
fn pem_body(pem: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(pem).ok()?;
    let body: String = text
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .ok()
}

/// Records which capabilities have been spent.
///
/// Implementations MUST be atomic: `consume` has to admit exactly one caller
/// for a given `jti`, even under concurrent use, or the single-use guarantee is
/// only advisory.
#[allow(async_fn_in_trait)]
pub trait ReplayStore {
    /// Atomically claims `jti`. Returns [`CapabilityError::Replayed`] if it was
    /// already claimed.
    ///
    /// This is `async` because the intended production implementation is a
    /// remote conditional write (DynamoDB, Redis); a synchronous seam would
    /// force `block_on` inside the caller's runtime.
    ///
    /// Implementations MUST be atomic: exactly one caller may win a given
    /// `jti`, even under concurrency, or the single-use guarantee is advisory.
    ///
    /// # Errors
    ///
    /// * [`CapabilityError::Replayed`] — already claimed.
    /// * [`CapabilityError::ReplayStoreUnavailable`] — the store was NOT reached
    ///   and the claim definitely did not happen; safe to retry.
    /// * [`CapabilityError::ReplayIndeterminate`] — the claim MAY have committed
    ///   but the outcome was lost. Return this rather than `Unavailable` for a
    ///   timeout or dropped reply on a write that could have landed.
    async fn consume(&self, jti: &str, expires_at: i64) -> Result<(), CapabilityError>;
}

/// An in-memory [`ReplayStore`], suitable for a single process.
///
/// Distributed brokers MUST supply a shared store instead; this one cannot see
/// uses made by another replica, so with more than one replica the single-use
/// guarantee silently weakens to per-process.
///
/// Entries are dropped once their capability has expired — a spent `jti` only
/// needs remembering for as long as the capability could still be presented.
/// Without that, the set grows without bound and becomes a memory-exhaustion
/// surface reachable by anyone who can cause capabilities to be issued.
pub struct InMemoryReplayStore {
    seen: Mutex<HashMap<String, i64>>,
    capacity: usize,
}

impl Default for InMemoryReplayStore {
    fn default() -> Self {
        Self::with_capacity(1_048_576)
    }
}

impl InMemoryReplayStore {
    /// Creates a store that will hold at most `capacity` unexpired entries.
    ///
    /// Reaching the cap is treated as a fault, not as licence to forget: the
    /// store fails closed with [`CapabilityError::ReplayStoreUnavailable`]
    /// rather than evicting a live `jti`, because evicting one would silently
    /// re-authorise it.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    /// Number of unexpired entries currently retained.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.lock().map(|s| s.len()).unwrap_or(0)
    }

    /// Whether the store currently retains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl std::fmt::Debug for InMemoryReplayStore {
    /// Renders the size only; `jti` values are replay-relevant.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryReplayStore")
            .field("retained", &self.len())
            .field("capacity", &self.capacity)
            .finish()
    }
}

impl ReplayStore for InMemoryReplayStore {
    async fn consume(&self, jti: &str, expires_at: i64) -> Result<(), CapabilityError> {
        let now = unix_now()?;
        let mut seen = self
            .seen
            .lock()
            .map_err(|_| CapabilityError::ReplayStoreUnavailable)?;

        // Drop entries whose capability can no longer be presented.
        seen.retain(|_, exp| *exp > now);

        if seen.contains_key(jti) {
            return Err(CapabilityError::Replayed);
        }
        if seen.len() >= self.capacity {
            // Fail closed. Evicting a live jti would silently re-authorise it.
            return Err(CapabilityError::ReplayStoreUnavailable);
        }
        seen.insert(jti.to_string(), expires_at);
        Ok(())
    }
}

/// The wire claims of a capability.
#[derive(Serialize, Deserialize)]
struct Claims {
    iss: String,
    aud: String,
    sub: String,
    tenant: String,
    op: Operation,
    /// Base64url of the framed request digest.
    req: String,
    iat: i64,
    nbf: i64,
    exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    jti: Option<String>,
}

/// Mints capabilities.
pub struct CapabilityIssuer<S: CapabilitySigner> {
    issuer: String,
    audience: String,
    signer: S,
}

impl<S: CapabilitySigner> std::fmt::Debug for CapabilityIssuer<S> {
    /// Renders without signer material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapabilityIssuer")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("signer", &"<redacted>")
            .finish()
    }
}

impl<S: CapabilitySigner> CapabilityIssuer<S> {
    /// Creates an issuer bound to one issuer identity and one audience.
    #[must_use]
    pub const fn new(issuer: String, audience: String, signer: S) -> Self {
        Self {
            issuer,
            audience,
            signer,
        }
    }

    /// Issues a capability valid for `ttl_seconds` from now.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityError::TtlTooLong`] if `ttl_seconds` exceeds
    /// [`MAX_TTL_SECONDS`], or a signing error.
    pub async fn issue(
        &self,
        subject: &str,
        request: &CapabilityRequest,
        ttl_seconds: u64,
    ) -> Result<String, CapabilityError> {
        self.issue_at(subject, request, ttl_seconds, unix_now()?)
            .await
    }

    /// Issues a capability whose validity starts at `iat`.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityError::TtlTooLong`] if `ttl_seconds` exceeds
    /// [`MAX_TTL_SECONDS`], or a signing error.
    pub async fn issue_at(
        &self,
        subject: &str,
        request: &CapabilityRequest,
        ttl_seconds: u64,
        iat: i64,
    ) -> Result<String, CapabilityError> {
        if ttl_seconds > MAX_TTL_SECONDS {
            return Err(CapabilityError::TtlTooLong);
        }
        self.mint(subject, request, ttl_seconds, iat, true).await
    }

    /// Mints a capability without the issuer-side TTL bound.
    ///
    /// Exists so the verifier's independent TTL check can be exercised against a
    /// non-conforming issuer. Never use this in production.
    ///
    /// # Errors
    ///
    /// Returns a signing error.
    #[doc(hidden)]
    pub async fn issue_unchecked_ttl_for_test(
        &self,
        subject: &str,
        request: &CapabilityRequest,
        ttl_seconds: u64,
    ) -> Result<String, CapabilityError> {
        self.mint(subject, request, ttl_seconds, unix_now()?, true)
            .await
    }

    /// Mints a capability with no `jti`.
    ///
    /// Exists so the verifier's missing-`jti` rejection can be exercised.
    /// Never use this in production.
    ///
    /// # Errors
    ///
    /// Returns a signing error.
    #[doc(hidden)]
    pub async fn issue_without_jti_for_test(
        &self,
        subject: &str,
        request: &CapabilityRequest,
        ttl_seconds: u64,
    ) -> Result<String, CapabilityError> {
        self.mint(subject, request, ttl_seconds, unix_now()?, false)
            .await
    }

    async fn mint(
        &self,
        subject: &str,
        request: &CapabilityRequest,
        ttl_seconds: u64,
        iat: i64,
        with_jti: bool,
    ) -> Result<String, CapabilityError> {
        let claims = Claims {
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            sub: subject.to_string(),
            tenant: request.tenant.clone(),
            op: request.operation,
            req: B64.encode(request.digest),
            iat,
            nbf: iat,
            exp: iat.saturating_add(ttl_seconds as i64),
            jti: with_jti.then(new_jti),
        };

        let header = B64.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let payload =
            B64.encode(serde_json::to_vec(&claims).map_err(|_| CapabilityError::SigningFailed)?);
        let signing_input = format!("{header}.{payload}");
        let signature = self.signer.sign(signing_input.as_bytes()).await?;
        Ok(format!("{signing_input}.{}", B64.encode(signature)))
    }
}

/// A capability that passed every check and was consumed exactly once.
pub struct VerifiedCapability {
    subject: String,
    tenant: String,
    operation: Operation,
    jti: String,
    expires_at: i64,
}

impl VerifiedCapability {
    /// The authorised subject.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// The authorised tenant.
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// The authorised operation.
    #[must_use]
    pub const fn operation(&self) -> Operation {
        self.operation
    }

    /// The consumed identifier.
    #[must_use]
    pub fn jti(&self) -> &str {
        &self.jti
    }

    /// The Unix timestamp at which the capability expired.
    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }
}

impl std::fmt::Debug for VerifiedCapability {
    /// Renders only non-identifying fields.
    ///
    /// `subject`, `tenant` and `jti` are all withheld: the first two identify
    /// who and whose data an operation touched, and the third is replay-relevant.
    /// A caller that genuinely needs them has typed accessors and can log them
    /// deliberately; what must not happen is a struct landing in a log line by
    /// accident and carrying them along.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedCapability")
            .field("subject", &"<redacted>")
            .field("tenant", &"<redacted>")
            .field("operation", &self.operation)
            .field("jti", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Verifies capabilities against pinned public key material.
pub struct CapabilityVerifier {
    issuer: String,
    audience: String,
    key: DecodingKey,
}

impl std::fmt::Debug for CapabilityVerifier {
    /// Renders without key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapabilityVerifier")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl CapabilityVerifier {
    /// Creates a verifier from an inline, pinned RSA public key in PEM form.
    ///
    /// Key material is supplied by the caller and never fetched over the
    /// network by this type.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityError::InvalidKey`] if the PEM cannot be parsed.
    pub fn from_rsa_pem(
        issuer: String,
        audience: String,
        pem: &[u8],
    ) -> Result<Self, CapabilityError> {
        // Enforce the SAME modulus bounds as the signer. jsonwebtoken will
        // happily accept a 1024-bit key; the signer will not. That asymmetry is
        // exactly what an attacker who supplies the key would reach for.
        let der = pem_body(pem).ok_or(CapabilityError::InvalidKey)?;
        let bits = spki_rsa_modulus_bits(&der).ok_or(CapabilityError::InvalidKey)?;
        if !(MIN_RSA_MODULUS_BITS..=MAX_RSA_MODULUS_BITS).contains(&bits) {
            return Err(CapabilityError::InvalidKey);
        }
        let key = DecodingKey::from_rsa_pem(pem).map_err(|_| CapabilityError::InvalidKey)?;
        Ok(Self {
            issuer,
            audience,
            key,
        })
    }

    /// Verifies a capability and consumes it exactly once.
    ///
    /// Signature, claims and request binding are all checked **before** the
    /// `jti` is consumed, so a capability rejected by any of those checks is
    /// not spent and may legitimately be presented again.
    ///
    /// That guarantee stops at the store boundary, and callers must not
    /// over-read it. Once [`ReplayStore::consume`] is entered the outcome is
    /// the store's to report:
    ///
    /// * [`CapabilityError::ReplayStoreUnavailable`] — not consumed; retryable.
    /// * [`CapabilityError::ReplayIndeterminate`] — MAY have been consumed.
    ///   Treat the capability as spent and obtain a new one; retrying risks the
    ///   double-use the `jti` exists to prevent.
    ///
    /// # Errors
    ///
    /// Returns the [`CapabilityError`] describing the first failed check.
    pub async fn verify<R: ReplayStore + ?Sized>(
        &self,
        token: &str,
        expected: &Expected,
        replay_store: &R,
    ) -> Result<VerifiedCapability, CapabilityError> {
        // RS256 is fixed here; the token's own `alg` header is never consulted.
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.required_spec_claims.clear();

        let claims = decode::<Claims>(token, &self.key, &validation)
            .map(|d| d.claims)
            .map_err(|e| {
                use jsonwebtoken::errors::ErrorKind;
                match e.kind() {
                    ErrorKind::InvalidIssuer => CapabilityError::IssuerMismatch,
                    ErrorKind::InvalidAudience => CapabilityError::AudienceMismatch,
                    ErrorKind::InvalidSignature => CapabilityError::BadSignature,
                    _ => CapabilityError::Malformed,
                }
            })?;

        let now = unix_now()?;
        if claims.exp.saturating_sub(claims.nbf) > MAX_TTL_SECONDS as i64 {
            return Err(CapabilityError::TtlTooLong);
        }
        if now >= claims.exp {
            return Err(CapabilityError::Expired);
        }
        if now < claims.nbf {
            return Err(CapabilityError::NotYetValid);
        }
        if claims.sub != expected.subject {
            return Err(CapabilityError::SubjectMismatch);
        }
        if claims.tenant != expected.request.tenant {
            return Err(CapabilityError::TenantMismatch);
        }
        if claims.op != expected.request.operation {
            return Err(CapabilityError::OperationMismatch);
        }
        if !constant_time_eq(
            claims.req.as_bytes(),
            B64.encode(expected.request.digest).as_bytes(),
        ) {
            return Err(CapabilityError::RequestMismatch);
        }

        let jti = claims.jti.ok_or(CapabilityError::MissingJti)?;
        replay_store.consume(&jti, claims.exp).await?;

        Ok(VerifiedCapability {
            subject: claims.sub,
            tenant: claims.tenant,
            operation: claims.op,
            jti,
            expires_at: claims.exp,
        })
    }
}

/// Compares two byte strings without early return on the first difference.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn new_jti() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn unix_now() -> Result<i64, CapabilityError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|_| CapabilityError::ClockUnavailable)
}
