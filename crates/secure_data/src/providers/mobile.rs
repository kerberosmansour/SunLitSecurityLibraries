//! Bounded native mobile wrap/unwrap adapter. Native bridges are trusted code.
//!
//! This module does not implement Keychain/Keystore or attest hardware. Native
//! implementations must enforce timeouts, terminate native work on cancellation,
//! clear transient key copies, and return posture bound to each operation.

use crate::error::DataError;
use crate::kms::{DataKey, KeyAlias, KeyProvider, WrappedDataKey};
use crate::mobile_storage::MobileStoragePolicy;
use std::future::Future;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Maximum native wrapped-key frame size in bytes.
pub const MAX_WRAPPED_KEY_BYTES: usize = 8192;

/// Value-free outcomes at the native key boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MobileKeyError {
    /// Request metadata or wrapped frame violates bounds.
    #[error("invalid mobile key request")]
    InvalidInput,
    /// Native operation returned inconsistent metadata or key material.
    #[error("invalid mobile key response")]
    InvalidResponse,
    /// Actual native custody does not satisfy policy.
    #[error("mobile custody policy rejected")]
    CustodyRejected,
    /// Existing native key cannot be found; decryption never recreates it.
    #[error("mobile key missing")]
    Missing,
    /// The device/key is locked.
    #[error("mobile key locked")]
    Locked,
    /// The native key was invalidated.
    #[error("mobile key invalidated")]
    Invalidated,
    /// Native service or bounded operation is unavailable.
    #[error("mobile key service unavailable")]
    Unavailable,
    /// Native operation did not complete atomically.
    #[error("mobile key operation incomplete")]
    Incomplete,
    /// Native wrapping authentication failed.
    #[error("mobile wrapping authentication failed")]
    AuthenticationFailed,
    /// Fresh key generation could not obtain operating-system entropy.
    #[error("mobile key entropy unavailable")]
    EntropyUnavailable,
}

/// Android's operation-bound key security level, not a device-wide claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AndroidSecurityLevel {
    /// Software-backed storage, accepted only by explicit policy.
    Software,
    /// Trusted execution environment.
    TrustedEnvironment,
    /// StrongBox hardware.
    StrongBox,
}

/// Custody returned by the native operation for the specific wrapping key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeCustody {
    /// iOS key attributes. Device-only storage alone is not hardware wrapping.
    Ios {
        /// Key accessibility is a device-only class.
        device_only: bool,
        /// Synchronization is enabled for this key.
        synchronized: bool,
        /// Key material is excluded from backups.
        backup_excluded: bool,
        /// This wrapping key is hardware backed, independently qualified.
        hardware_backed: bool,
    },
    /// Android key level returned for this operation.
    Android(AndroidSecurityLevel),
}

/// Explicit platform requirement, combined with MobileStoragePolicy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MobilePlatformPolicy {
    /// Require iOS device-only, nonsynchronized, backup-excluded custody.
    IosDeviceOnly,
    /// Accept Android software or hardware, unless storage policy requires hardware.
    AndroidSoftwareAllowed,
    /// Require Android TEE or StrongBox.
    AndroidHardwareRequired,
    /// Require Android StrongBox specifically.
    AndroidStrongBoxRequired,
}

/// Successful native wrapping response. Does not contain a KEK or plaintext DEK.
/// No Debug implementation: consumers must not log native response material.
pub struct NativeWrappedKey {
    /// Exact alias used by the completed operation.
    pub alias: String,
    /// Nonempty bounded native key version.
    pub version: String,
    /// Authenticated native wrapped-key frame, at most MAX_WRAPPED_KEY_BYTES.
    pub wrapped_key: WrappedDataKey,
    /// Actual custody of the key used for this operation.
    pub custody: NativeCustody,
}

/// Successful native unwrap response, using zeroizing ownership immediately.
/// No Debug implementation: consumers must not log transient key material.
pub struct NativeUnwrappedKey {
    /// Exact alias used by the completed operation.
    pub alias: String,
    /// Exact version used by the completed operation.
    pub version: String,
    /// Exactly 32 bytes; native implementation must clear its transient copies.
    pub data_key: DataKey,
    /// Actual custody of the key used for this operation.
    pub custody: NativeCustody,
}

/// Trusted native bridge, following Guardian's platform bridge pattern.
///
/// Implementations must keep KEKs native, cryptographically bind frames to
/// alias/version, enforce response/allocation/time bounds, and clear native DEK
/// copies on success, error and cancellation. An unwrap must never create a key.
/// Return metadata/posture from the completed operation, not a separate preflight.
/// The adapter cannot verify the truthfulness of a native implementation.
pub trait NativeKeyBridge: Send {
    /// Wrap a transient DEK. Native creation/rotation belongs only to this path.
    fn wrap(
        &mut self,
        alias: &str,
        data_key: &[u8],
    ) -> impl Future<Output = Result<NativeWrappedKey, MobileKeyError>> + Send;

    /// Unwrap an existing frame without recreation or implicit retry.
    fn unwrap(
        &mut self,
        alias: &str,
        version: &str,
        wrapped_key: &[u8],
    ) -> impl Future<Output = Result<NativeUnwrappedKey, MobileKeyError>> + Send;
}

/// Sealed KeyProvider adapting a reviewed native mobile bridge to real envelopes.
/// Clones share one serialized native operation lane. Independent instances must
/// be coordinated by the native implementation when sharing the same key store.
pub struct MobileKeyProvider<B> {
    bridge: Arc<Mutex<B>>,
    platform: MobilePlatformPolicy,
    require_hardware: bool,
}

impl<B: NativeKeyBridge> MobileKeyProvider<B> {
    /// Construct a provider. No native key creation or posture preflight occurs.
    #[must_use]
    pub fn new(bridge: B, platform: MobilePlatformPolicy, storage: MobileStoragePolicy) -> Self {
        Self {
            bridge: Arc::new(Mutex::new(bridge)),
            platform,
            require_hardware: storage.requires_hardware_keystore(),
        }
    }
}

impl<B> Clone for MobileKeyProvider<B> {
    fn clone(&self) -> Self {
        Self {
            bridge: Arc::clone(&self.bridge),
            platform: self.platform,
            require_hardware: self.require_hardware,
        }
    }
}

impl<B: NativeKeyBridge> crate::kms::private::Sealed for MobileKeyProvider<B> {}

fn valid_identifier(value: &str, bound: usize) -> bool {
    !value.is_empty() && value.len() <= bound && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn failure(kind: MobileKeyError) -> DataError {
    DataError::MobileKeyProvider { kind }
}

impl<B: NativeKeyBridge> MobileKeyProvider<B> {
    fn check_custody(&self, custody: NativeCustody) -> Result<(), DataError> {
        let (platform_ok, hardware) = match (self.platform, custody) {
            (
                MobilePlatformPolicy::IosDeviceOnly,
                NativeCustody::Ios {
                    device_only,
                    synchronized,
                    backup_excluded,
                    hardware_backed,
                },
            ) => (
                device_only && !synchronized && backup_excluded,
                hardware_backed,
            ),
            (MobilePlatformPolicy::AndroidSoftwareAllowed, NativeCustody::Android(level)) => {
                (true, level != AndroidSecurityLevel::Software)
            }
            (MobilePlatformPolicy::AndroidHardwareRequired, NativeCustody::Android(level)) => (
                level != AndroidSecurityLevel::Software,
                level != AndroidSecurityLevel::Software,
            ),
            (MobilePlatformPolicy::AndroidStrongBoxRequired, NativeCustody::Android(level)) => (
                level == AndroidSecurityLevel::StrongBox,
                level != AndroidSecurityLevel::Software,
            ),
            _ => (false, false),
        };
        if platform_ok && (!self.require_hardware || hardware) {
            Ok(())
        } else {
            Err(failure(MobileKeyError::CustodyRejected))
        }
    }
}

impl<B: NativeKeyBridge> KeyProvider for MobileKeyProvider<B> {
    async fn generate_data_key(
        &self,
        alias: &KeyAlias,
    ) -> Result<(DataKey, WrappedDataKey, String), DataError> {
        use rand::RngCore;
        use zeroize::Zeroizing;
        if !valid_identifier(alias, 128) {
            return Err(failure(MobileKeyError::InvalidInput));
        }
        // Allocate under zeroizing ownership before obtaining any secret bytes.
        let mut data_key = Zeroizing::new(vec![0u8; 32]);
        rand::rngs::OsRng
            .try_fill_bytes(&mut data_key)
            .map_err(|_| failure(MobileKeyError::EntropyUnavailable))?;
        let mut bridge = self.bridge.lock().await;
        let response = bridge.wrap(alias, &data_key).await.map_err(failure)?;
        if response.alias != alias
            || !valid_identifier(&response.version, 64)
            || response.wrapped_key.is_empty()
            || response.wrapped_key.len() > MAX_WRAPPED_KEY_BYTES
        {
            return Err(failure(MobileKeyError::InvalidResponse));
        }
        self.check_custody(response.custody)?;
        Ok((data_key, response.wrapped_key, response.version))
    }

    async fn unwrap_data_key(
        &self,
        wrapped: &WrappedDataKey,
        alias: &KeyAlias,
        version: &str,
    ) -> Result<DataKey, DataError> {
        if !valid_identifier(alias, 128)
            || !valid_identifier(version, 64)
            || wrapped.is_empty()
            || wrapped.len() > MAX_WRAPPED_KEY_BYTES
        {
            return Err(failure(MobileKeyError::InvalidInput));
        }
        let mut bridge = self.bridge.lock().await;
        let response = bridge
            .unwrap(alias, version, wrapped)
            .await
            .map_err(failure)?;
        if response.alias != alias || response.version != version || response.data_key.len() != 32 {
            return Err(failure(MobileKeyError::InvalidResponse));
        }
        self.check_custody(response.custody)?;
        Ok(response.data_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{decrypt_for_use, encrypt_for_storage};
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Nonce,
    };
    use rand::{Rng, RngCore};
    use security_core::classification::DataClassification;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex as StdMutex,
    };
    use zeroize::Zeroizing;

    struct State {
        key: Zeroizing<[u8; 32]>,
        custody: NativeCustody,
        error: Option<MobileKeyError>,
        malformed: bool,
        bad_metadata: bool,
        oversized: bool,
        empty_frame: bool,
        bad_version: bool,
        wraps: usize,
        unwraps: usize,
    }
    struct TestBridge {
        state: Arc<StdMutex<State>>,
        active: Arc<AtomicUsize>,
        maximum: Arc<AtomicUsize>,
    }
    impl NativeKeyBridge for TestBridge {
        async fn wrap(
            &mut self,
            alias: &str,
            key: &[u8],
        ) -> Result<NativeWrappedKey, MobileKeyError> {
            let now = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.maximum.fetch_max(now, Ordering::SeqCst);
            tokio::task::yield_now().await;
            self.active.fetch_sub(1, Ordering::SeqCst);
            let mut s = self.state.lock().unwrap();
            s.wraps += 1;
            if let Some(error) = s.error {
                return Err(error);
            }
            // Test-only native stand-in; never exposed as a production backend.
            let cipher = Aes256Gcm::new_from_slice(s.key.as_ref()).unwrap();
            let nonce: [u8; 12] = rand::rngs::OsRng.gen();
            let aad = format!("{alias}:v1");
            let mut frame = nonce.to_vec();
            frame.extend(
                cipher
                    .encrypt(
                        Nonce::from_slice(&nonce),
                        Payload {
                            msg: key,
                            aad: aad.as_bytes(),
                        },
                    )
                    .unwrap(),
            );
            if s.oversized {
                frame.resize(MAX_WRAPPED_KEY_BYTES + 1, 0);
            }
            if s.empty_frame {
                frame.clear();
            }
            Ok(NativeWrappedKey {
                alias: if s.bad_metadata {
                    "wrong".into()
                } else {
                    alias.into()
                },
                version: if s.bad_version {
                    "x".repeat(65)
                } else {
                    "v1".into()
                },
                wrapped_key: frame,
                custody: s.custody,
            })
        }
        async fn unwrap(
            &mut self,
            alias: &str,
            version: &str,
            wrapped: &[u8],
        ) -> Result<NativeUnwrappedKey, MobileKeyError> {
            let now = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.maximum.fetch_max(now, Ordering::SeqCst);
            tokio::task::yield_now().await;
            self.active.fetch_sub(1, Ordering::SeqCst);
            let mut s = self.state.lock().unwrap();
            s.unwraps += 1;
            if let Some(error) = s.error {
                return Err(error);
            }
            if wrapped.len() < 28 {
                return Err(MobileKeyError::AuthenticationFailed);
            }
            let cipher = Aes256Gcm::new_from_slice(s.key.as_ref()).unwrap();
            let aad = format!("{alias}:{version}");
            let mut key = Zeroizing::new(
                cipher
                    .decrypt(
                        Nonce::from_slice(&wrapped[..12]),
                        Payload {
                            msg: &wrapped[12..],
                            aad: aad.as_bytes(),
                        },
                    )
                    .map_err(|_| MobileKeyError::AuthenticationFailed)?,
            );
            if s.malformed {
                key.truncate(31);
            }
            Ok(NativeUnwrappedKey {
                alias: if s.bad_metadata {
                    "wrong".into()
                } else {
                    alias.into()
                },
                version: if s.bad_version {
                    "wrong-version".into()
                } else {
                    version.into()
                },
                data_key: key,
                custody: s.custody,
            })
        }
    }
    fn backend(custody: NativeCustody) -> (TestBridge, Arc<StdMutex<State>>, Arc<AtomicUsize>) {
        let mut key = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(key.as_mut());
        let state = Arc::new(StdMutex::new(State {
            key,
            custody,
            error: None,
            malformed: false,
            bad_metadata: false,
            oversized: false,
            empty_frame: false,
            bad_version: false,
            wraps: 0,
            unwraps: 0,
        }));
        let maximum = Arc::new(AtomicUsize::new(0));
        (
            TestBridge {
                state: Arc::clone(&state),
                active: Arc::new(AtomicUsize::new(0)),
                maximum: Arc::clone(&maximum),
            },
            state,
            maximum,
        )
    }
    fn provider(
        bridge: TestBridge,
        policy: MobilePlatformPolicy,
        hardware: bool,
    ) -> MobileKeyProvider<TestBridge> {
        let storage = if hardware {
            MobileStoragePolicy::hardware_backed(DataClassification::Secret)
        } else {
            MobileStoragePolicy::encrypted(DataClassification::Confidential)
        };
        MobileKeyProvider::new(bridge, policy, storage)
    }
    fn mobile_error<T>(result: Result<T, DataError>, kind: MobileKeyError) {
        assert!(matches!(result, Err(DataError::MobileKeyProvider {kind:k}) if k==kind));
    }

    #[tokio::test]
    async fn oc_mobile_key_provider_1_persist_restart_and_tamper_never_returns_plaintext() {
        let custody = NativeCustody::Android(AndroidSecurityLevel::TrustedEnvironment);
        let (bridge, state, _) = backend(custody);
        let p = provider(bridge, MobilePlatformPolicy::AndroidHardwareRequired, true);
        let mut plaintext = [0u8; 48];
        rand::rngs::OsRng.fill_bytes(&mut plaintext);
        let one = encrypt_for_storage(&plaintext, "app-key", &p)
            .await
            .unwrap();
        let two = encrypt_for_storage(&plaintext, "app-key", &p)
            .await
            .unwrap();
        assert_ne!(one.wrapped_data_key, two.wrapped_data_key);
        let (unrelated, _, _) = backend(custody);
        let unrelated = provider(
            unrelated,
            MobilePlatformPolicy::AndroidHardwareRequired,
            true,
        );
        assert!(
            decrypt_for_use(&one, &unrelated).await.is_err(),
            "a new native store must not recover the old native key"
        );
        let encoded = serde_json::to_vec(&one).unwrap();
        drop(p);
        let (mut bridge, _, _) = backend(custody);
        bridge.state = Arc::clone(&state);
        let reopened = provider(bridge, MobilePlatformPolicy::AndroidHardwareRequired, true);
        let persisted = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(
            decrypt_for_use(&persisted, &reopened)
                .await
                .unwrap()
                .as_slice(),
            plaintext
        );
        for case in 0..4 {
            let mut changed = one.clone();
            match case {
                0 => changed.ciphertext[0] ^= 1,
                1 => changed.wrapped_data_key[13] ^= 1,
                2 => changed.key_alias = "other".into(),
                _ => changed.key_version = "v2".into(),
            }
            assert!(decrypt_for_use(&changed, &reopened).await.is_err());
        }
        assert_eq!(state.lock().unwrap().wraps, 2);
        state.lock().unwrap().error = Some(MobileKeyError::Invalidated);
        mobile_error(
            decrypt_for_use(&one, &reopened).await,
            MobileKeyError::Invalidated,
        );
        assert_eq!(
            state.lock().unwrap().wraps,
            2,
            "decrypt must not create native keys"
        );
    }

    #[tokio::test]
    async fn given_invalid_requests_then_native_operations_are_not_called() {
        let (b, s, _) = backend(NativeCustody::Android(AndroidSecurityLevel::Software));
        let p = provider(b, MobilePlatformPolicy::AndroidSoftwareAllowed, false);
        for alias in [
            "".to_string(),
            "x".repeat(129),
            "line\nkey".into(),
            "é".into(),
        ] {
            mobile_error(
                p.generate_data_key(&alias).await,
                MobileKeyError::InvalidInput,
            );
        }
        for (frame, version) in [
            (vec![], "v1".into()),
            (vec![0; 8193], "v1".into()),
            (vec![0; 1], "".into()),
            (vec![0; 1], "x".repeat(65)),
        ] {
            mobile_error(
                p.unwrap_data_key(&frame, "key", &version).await,
                MobileKeyError::InvalidInput,
            );
        }
        let s = s.lock().unwrap();
        assert_eq!((s.wraps, s.unwraps), (0, 0));
    }

    #[tokio::test]
    async fn given_android_levels_then_explicit_policy_distinguishes_software_tee_strongbox() {
        for level in [
            AndroidSecurityLevel::Software,
            AndroidSecurityLevel::TrustedEnvironment,
            AndroidSecurityLevel::StrongBox,
        ] {
            for policy in [
                MobilePlatformPolicy::AndroidSoftwareAllowed,
                MobilePlatformPolicy::AndroidHardwareRequired,
                MobilePlatformPolicy::AndroidStrongBoxRequired,
            ] {
                let (b, _, _) = backend(NativeCustody::Android(level));
                let p = provider(b, policy, false);
                let accepted = matches!(policy, MobilePlatformPolicy::AndroidSoftwareAllowed)
                    || (matches!(policy, MobilePlatformPolicy::AndroidHardwareRequired)
                        && level != AndroidSecurityLevel::Software)
                    || level == AndroidSecurityLevel::StrongBox;
                let result = p.generate_data_key("key").await;
                if accepted {
                    assert!(result.is_ok());
                } else {
                    mobile_error(result, MobileKeyError::CustodyRejected);
                }
            }
        }
        let (b, _, _) = backend(NativeCustody::Android(AndroidSecurityLevel::Software));
        mobile_error(
            provider(b, MobilePlatformPolicy::AndroidSoftwareAllowed, true)
                .generate_data_key("key")
                .await,
            MobileKeyError::CustodyRejected,
        );
    }

    #[tokio::test]
    async fn given_ios_sync_backup_or_nondevice_custody_then_reject() {
        for (device_only, synchronized, backup_excluded, accepted) in [
            (true, false, true, true),
            (false, false, true, false),
            (true, true, true, false),
            (true, false, false, false),
        ] {
            let (b, _, _) = backend(NativeCustody::Ios {
                device_only,
                synchronized,
                backup_excluded,
                hardware_backed: false,
            });
            let result = provider(b, MobilePlatformPolicy::IosDeviceOnly, false)
                .generate_data_key("key")
                .await;
            if accepted {
                assert!(result.is_ok());
            } else {
                mobile_error(result, MobileKeyError::CustodyRejected);
            }
        }
        let (b, _, _) = backend(NativeCustody::Ios {
            device_only: true,
            synchronized: false,
            backup_excluded: true,
            hardware_backed: false,
        });
        mobile_error(
            provider(b, MobilePlatformPolicy::IosDeviceOnly, true)
                .generate_data_key("key")
                .await,
            MobileKeyError::CustodyRejected,
        );
        let (b, _, _) = backend(NativeCustody::Android(AndroidSecurityLevel::StrongBox));
        mobile_error(
            provider(b, MobilePlatformPolicy::IosDeviceOnly, true)
                .generate_data_key("key")
                .await,
            MobileKeyError::CustodyRejected,
        );
    }

    #[tokio::test]
    async fn given_native_failures_then_fixed_error_once_without_retry() {
        for kind in [
            MobileKeyError::Missing,
            MobileKeyError::Locked,
            MobileKeyError::Invalidated,
            MobileKeyError::Unavailable,
            MobileKeyError::Incomplete,
            MobileKeyError::AuthenticationFailed,
        ] {
            let (b, s, _) = backend(NativeCustody::Android(AndroidSecurityLevel::StrongBox));
            s.lock().unwrap().error = Some(kind);
            let p = provider(b, MobilePlatformPolicy::AndroidHardwareRequired, true);
            mobile_error(p.generate_data_key("secret-alias").await, kind);
            mobile_error(
                p.unwrap_data_key(&vec![0; 32], "secret-alias", "v1").await,
                kind,
            );
            {
                let state = s.lock().unwrap();
                assert_eq!((state.wraps, state.unwraps), (1, 1));
            }
            assert!(!DataError::MobileKeyProvider { kind }
                .to_string()
                .contains("secret-alias"));
        }
    }

    #[tokio::test]
    async fn given_malformed_native_responses_then_no_key_reaches_aead() {
        let (b, s, _) = backend(NativeCustody::Android(AndroidSecurityLevel::StrongBox));
        let p = provider(b, MobilePlatformPolicy::AndroidHardwareRequired, true);
        s.lock().unwrap().bad_metadata = true;
        mobile_error(
            p.generate_data_key("key").await,
            MobileKeyError::InvalidResponse,
        );
        s.lock().unwrap().bad_metadata = false;
        s.lock().unwrap().oversized = true;
        mobile_error(
            p.generate_data_key("key").await,
            MobileKeyError::InvalidResponse,
        );
        s.lock().unwrap().oversized = false;
        s.lock().unwrap().empty_frame = true;
        mobile_error(
            p.generate_data_key("key").await,
            MobileKeyError::InvalidResponse,
        );
        s.lock().unwrap().empty_frame = false;
        s.lock().unwrap().bad_version = true;
        mobile_error(
            p.generate_data_key("key").await,
            MobileKeyError::InvalidResponse,
        );
        s.lock().unwrap().bad_version = false;
        let envelope = encrypt_for_storage(b"record", "key", &p).await.unwrap();
        s.lock().unwrap().bad_version = true;
        mobile_error(
            decrypt_for_use(&envelope, &p).await,
            MobileKeyError::InvalidResponse,
        );
        s.lock().unwrap().bad_version = false;
        s.lock().unwrap().malformed = true;
        mobile_error(
            decrypt_for_use(&envelope, &p).await,
            MobileKeyError::InvalidResponse,
        );
        s.lock().unwrap().malformed = false;
        s.lock().unwrap().bad_metadata = true;
        mobile_error(
            decrypt_for_use(&envelope, &p).await,
            MobileKeyError::InvalidResponse,
        );
        s.lock().unwrap().bad_metadata = false;
        s.lock().unwrap().custody = NativeCustody::Android(AndroidSecurityLevel::Software);
        mobile_error(
            decrypt_for_use(&envelope, &p).await,
            MobileKeyError::CustodyRejected,
        );
    }

    #[tokio::test]
    async fn given_concurrent_provider_clones_then_one_native_operation_at_a_time() {
        let (b, _, maximum) = backend(NativeCustody::Android(AndroidSecurityLevel::StrongBox));
        let p = provider(b, MobilePlatformPolicy::AndroidHardwareRequired, true);
        let second = p.clone();
        let (one, two) = tokio::join!(p.generate_data_key("key"), second.generate_data_key("key"));
        assert!(one.is_ok() && two.is_ok());
        assert_eq!(maximum.load(Ordering::SeqCst), 1);
        assert_ne!(one.unwrap().0.as_slice(), two.unwrap().0.as_slice());
    }
    #[tokio::test]
    async fn given_wrap_unwrap_and_unwrap_unwrap_then_all_use_the_shared_lane() {
        let (b, _, maximum) = backend(NativeCustody::Android(AndroidSecurityLevel::StrongBox));
        let p = provider(b, MobilePlatformPolicy::AndroidHardwareRequired, true);
        let (_, wrapped, version) = p.generate_data_key("key").await.unwrap();
        maximum.store(0, Ordering::SeqCst);
        let (wrap, unwrap) = tokio::join!(
            p.generate_data_key("key"),
            p.unwrap_data_key(&wrapped, "key", &version)
        );
        assert!(wrap.is_ok() && unwrap.is_ok());
        assert_eq!(maximum.load(Ordering::SeqCst), 1);
        maximum.store(0, Ordering::SeqCst);
        let (one, two) = tokio::join!(
            p.unwrap_data_key(&wrapped, "key", &version),
            p.unwrap_data_key(&wrapped, "key", &version)
        );
        assert!(one.is_ok() && two.is_ok());
        assert_eq!(maximum.load(Ordering::SeqCst), 1);
        assert_eq!(one.unwrap().as_slice(), two.unwrap().as_slice());
    }
}
