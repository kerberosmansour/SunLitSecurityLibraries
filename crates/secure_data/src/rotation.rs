// Key rotation and re-encryption helpers.

use crate::envelope::{decrypt_for_use, encrypt_for_storage, EnvelopeEncrypted};
use crate::error::DataError;
use crate::kms::KeyProvider;

/// A plan for rotating a key: source alias/version → target alias.
///
/// # Examples
///
/// ```
/// use secure_data::rotation::RotationPlan;
///
/// let plan = RotationPlan::new("old-key".into(), "new-key".into());
/// assert_eq!(plan.source_alias, "old-key");
/// assert_eq!(plan.target_alias, "new-key");
/// ```
#[derive(Debug, Clone)]
pub struct RotationPlan {
    /// The alias of the current key.
    pub source_alias: String,
    /// The target alias to rotate to.
    pub target_alias: String,
}

impl RotationPlan {
    /// Creates a new rotation plan.
    #[must_use]
    pub fn new(source_alias: String, target_alias: String) -> Self {
        Self {
            source_alias,
            target_alias,
        }
    }
}

/// Re-encrypts data from the key in `old_envelope` to a new key identified by `new_key_alias`.
///
/// During the rotation window both the old and new envelopes decrypt to the same plaintext,
/// enabling dual-read patterns (i.e. the old envelope is still valid until migrated).
///
/// # Errors
/// Returns [`DataError`] if decryption or re-encryption fails.
pub async fn re_encrypt<P: KeyProvider>(
    old_envelope: &EnvelopeEncrypted,
    new_key_alias: &str,
    provider: &P,
) -> Result<EnvelopeEncrypted, DataError> {
    // 1. Decrypt the existing envelope to recover the plaintext.
    let plaintext = decrypt_for_use(old_envelope, provider).await?;

    // 2. Re-encrypt under the new key alias.
    encrypt_for_storage(&plaintext, new_key_alias, provider).await
}
