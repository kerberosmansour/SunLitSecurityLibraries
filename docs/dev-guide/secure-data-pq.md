# `secure_data` Post-Quantum Envelope Wrap

Enable the `pq` feature when new envelopes need hybrid X25519 + ML-KEM-768 key wrap:

```bash
cargo add secure_data --features pq
```

```rust,ignore
use secure_data::algorithm::{AlgorithmPolicy, CryptoAlgorithm};
use secure_data::envelope::{decrypt_for_use, encrypt_with_policy};
use secure_data::kms::StaticDevKeyProvider;

# async fn example() -> Result<(), secure_data::error::DataError> {
let provider = StaticDevKeyProvider::new();
let policy = AlgorithmPolicy::prefer(CryptoAlgorithm::HybridX25519MlKem768);

let envelope = encrypt_with_policy(b"customer record", "default", &provider, &policy).await?;
assert_eq!(envelope.version, "2");
assert_eq!(envelope.combiner_id, Some(0x01));

let recovered = decrypt_for_use(&envelope, &provider).await?;
assert_eq!(recovered, b"customer record");
# Ok(())
# }
```

## Wire Shape

Hybrid envelopes set:

| Field | Value |
|---|---|
| `version` | `"2"` |
| `algorithm` | `"X25519+ML-KEM-768/HKDF-SHA-256"` |
| `combiner_id` | `Some(0x01)` |
| `wrapped_data_key` | `ML-KEM-768 ciphertext || X25519 share || AES-GCM-wrapped DEK` |

The HKDF info string is `sunlit-pq-x25519-ml-kem-768/v1`. The AAD binds `version`, `algorithm`, `key_alias`, `key_version`, and `combiner_id`, so metadata tampering fails before plaintext is released.

## Provider Interaction

The `KeyProvider` trait is unchanged. M2 derives a per-envelope hybrid recipient seed from provider-protected key material, stores the provider-wrapped seed inside the existing hybrid metadata, and uses the ML-KEM/X25519 result to wrap the actual data-encryption key. Existing provider implementations do not need PQ-specific APIs.

## Failure Modes

| Situation | Result |
|---|---|
| Selecting `HybridX25519MlKem768` without `--features pq` | `DataError::PqUnavailable` |
| Reading a v2 hybrid envelope without `--features pq` | `DataError::PqFeatureRequired` |
| Tampered ML-KEM ciphertext, X25519 share, wrapped DEK, or AAD | decrypt fails; plaintext is not returned |
| `combiner_id = 0xFF` | rejected fail-closed before cryptographic work |

## Status

The default `pq` backend is RustCrypto `ml-kem` v0.3.0 plus `x25519-dalek`, `hkdf`, and `sha2`. The runtime status label is `pending_cmvp`; do not present this path as validated under FIPS 140.
