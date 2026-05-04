// Key provider abstraction and StaticDevKeyProvider for tests.
//
// Application code calls encrypt_for_storage() / decrypt_for_use() —
// never the underlying AEAD primitives directly.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::error::DataError;

/// The raw bytes of a data-encryption key (DEK).
pub type DataKey = Zeroizing<Vec<u8>>;

/// A data-encryption key wrapped (encrypted) by the key-encryption key (KEK).
pub type WrappedDataKey = Vec<u8>;

/// An alias identifying a named key in the key provider.
pub type KeyAlias = str;

/// Sealing trait — prevents external implementations.
pub(crate) mod private {
    pub trait Sealed {}
}

/// Pluggable key-provider abstraction.
///
/// All methods are `async fn` (native, no `async-trait` crate).
/// The trait is sealed to prevent external implementations breaking internal invariants.
pub trait KeyProvider: private::Sealed + Send + Sync {
    /// Generates a new data-encryption key under the given alias, returning both the
    /// plaintext key and its wrapped (KEK-encrypted) form.
    fn generate_data_key(
        &self,
        alias: &KeyAlias,
    ) -> impl Future<Output = Result<(DataKey, WrappedDataKey, String), DataError>> + Send;

    /// Unwraps (decrypts) a previously generated wrapped data key.
    fn unwrap_data_key(
        &self,
        wrapped: &WrappedDataKey,
        alias: &KeyAlias,
        version: &str,
    ) -> impl Future<Output = Result<DataKey, DataError>> + Send;
}

/// A static, in-memory key provider for testing and development.
///
/// **Never use in production.** Keys are stored unencrypted in memory.
///
/// # Examples
///
/// ```
/// use secure_data::kms::StaticDevKeyProvider;
///
/// let provider = StaticDevKeyProvider::new();
/// ```
pub struct StaticDevKeyProvider {
    keys: Arc<Mutex<HashMap<String, Zeroizing<Vec<u8>>>>>,
}

impl StaticDevKeyProvider {
    /// Creates a new `StaticDevKeyProvider` with a fixed 32-byte key for `"default"`.
    #[must_use]
    pub fn new() -> Self {
        let mut keys = HashMap::new();
        // Fixed 256-bit key for the default alias (dev/test only)
        keys.insert("default".to_string(), Zeroizing::new(vec![0x42u8; 32]));
        Self {
            keys: Arc::new(Mutex::new(keys)),
        }
    }

    /// Returns the KEK bytes for an alias, creating a deterministic one if absent.
    async fn kek_for(&self, alias: &str) -> Zeroizing<Vec<u8>> {
        let mut map = self.keys.lock().await;
        if let Some(k) = map.get(alias) {
            return k.clone();
        }
        // Derive a deterministic test key from the alias bytes (dev only)
        let mut key = vec![0u8; 32];
        for (i, b) in alias.bytes().enumerate() {
            key[i % 32] ^= b;
        }
        // Ensure key is non-zero
        key[0] |= 0x01;
        let kek = Zeroizing::new(key);
        map.insert(alias.to_string(), kek.clone());
        kek
    }
}

impl Default for StaticDevKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl private::Sealed for StaticDevKeyProvider {}

impl KeyProvider for StaticDevKeyProvider {
    fn generate_data_key(
        &self,
        alias: &KeyAlias,
    ) -> impl Future<Output = Result<(DataKey, WrappedDataKey, String), DataError>> + Send {
        let alias = alias.to_string();
        let keys = Arc::clone(&self.keys);
        async move {
            // Generate a random 32-byte DEK
            use rand::RngCore;
            let mut dek = vec![0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut dek);
            let dek = Zeroizing::new(dek);

            // "Wrap" the DEK by XOR with the KEK (dev only — not secure for production)
            let provider = StaticDevKeyProvider {
                keys: Arc::clone(&keys),
            };
            let kek = provider.kek_for(&alias).await;
            let wrapped: Vec<u8> = dek
                .iter()
                .zip(kek.iter().cycle())
                .map(|(d, k)| d ^ k)
                .collect();

            Ok((dek, wrapped, "v1".to_string()))
        }
    }

    fn unwrap_data_key(
        &self,
        wrapped: &WrappedDataKey,
        alias: &KeyAlias,
        _version: &str,
    ) -> impl Future<Output = Result<DataKey, DataError>> + Send {
        let alias = alias.to_string();
        let wrapped = wrapped.clone();
        let keys = Arc::clone(&self.keys);
        async move {
            let provider = StaticDevKeyProvider {
                keys: Arc::clone(&keys),
            };
            let kek = provider.kek_for(&alias).await;
            let dek: Vec<u8> = wrapped
                .iter()
                .zip(kek.iter().cycle())
                .map(|(w, k)| w ^ k)
                .collect();
            Ok(Zeroizing::new(dek))
        }
    }
}
