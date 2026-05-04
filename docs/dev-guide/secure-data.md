# `secure_data` — Developer Guide

> **OWASP C8**: Data protection — secrets management, envelope encryption, key rotation, and FIPS readiness.

`secure_data` ensures that sensitive data is never stored in plaintext and that secrets are never accidentally logged or serialized. It provides typed secret wrappers, envelope encryption with pluggable KMS backends, and a key lifecycle management system.

---

## Quick Start

```toml
[dependencies]
secure_data = { path = "../secure_data" }

# With optional features:
secure_data = { path = "../secure_data", features = ["vault"] }       # HashiCorp Vault
secure_data = { path = "../secure_data", features = ["aws-kms"] }     # AWS KMS
secure_data = { path = "../secure_data", features = ["fips"] }        # FIPS 140-2/3 backend
secure_data = { path = "../secure_data", features = ["vault", "aws-kms"] } # Both
```

---

## Secret Types

Application code should **never** hold raw `String` for secrets. Use typed wrappers that automatically redact in `Debug`, `Display`, and `Serialize`:

### `SecretString` — General-Purpose Secret

```rust
use secure_data::secret::SecretString;

let password = SecretString::new("my-database-password".to_string());

// Debug is redacted — safe for logging
println!("{:?}", password);
// → SecretString([REDACTED])

// Serialize is redacted — safe for JSON responses
let json = serde_json::to_string(&password).unwrap();
assert_eq!(json, "\"[REDACTED]\"");

// Explicit access when needed (e.g., passing to a database driver)
let actual: &str = password.expose_secret();
assert_eq!(actual, "my-database-password");

// Memory is zeroed on drop (via zeroize)
```

### `SecretBytes` — Raw Secret Bytes

```rust
use secure_data::secret::SecretBytes;

let key_material = SecretBytes::new(vec![0x42; 32]);

println!("{:?}", key_material);
// → SecretBytes([REDACTED] 32 bytes)

let raw: &[u8] = key_material.expose_secret();
```

### Domain-Specific Secret Types

```rust
use secure_data::secret::{ApiToken, DbPassword, SigningKeyRef};

let token = ApiToken::new("example-api-token".to_string());
let db_pass = DbPassword::new("postgres-secret".to_string());
let signing = SigningKeyRef::new("keys/signing-v2".to_string());

// All behave the same: Debug/Display → [REDACTED], expose via expose_secret()
println!("{:?}", token);    // → ApiToken([REDACTED])
println!("{:?}", db_pass);  // → DbPassword([REDACTED])
println!("{:?}", signing);  // → SigningKeyRef([REDACTED])
```

### `ReadOnce<T>` — Single-Use Secret

For secrets that should only be read once (e.g., initial key material):

```rust
use secure_data::memory::ReadOnce;

let mut secret = ReadOnce::new("one-time-password".to_string());

// First read — succeeds
let value = secret.take(); // Some("one-time-password")

// Second read — empty (value was consumed)
let value = secret.take(); // None

// Debug is always safe
println!("{:?}", secret); // → <consumed>

// Memory is zeroed on drop
```

---

## Envelope Encryption

Envelope encryption separates the data encryption key (DEK) from the key encryption key (KEK). Your application never handles raw AEAD directly:

```
┌─────────────────────────────────────────┐
│  encrypt_for_storage(plaintext, alias)  │
│                                         │
│  1. KeyProvider generates random DEK    │
│  2. DEK encrypts plaintext (AES-256-GCM)│
│  3. KEK wraps DEK                       │
│  4. Returns EnvelopeEncrypted           │
│     (ciphertext + wrapped_dek + nonce)  │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│  decrypt_for_use(envelope, provider)    │
│                                         │
│  1. KEK unwraps DEK                     │
│  2. DEK decrypts ciphertext             │
│  3. Returns plaintext                   │
│  4. DEK is zeroized from memory         │
└─────────────────────────────────────────┘
```

### Basic Usage

```rust
use secure_data::envelope::{encrypt_for_storage, decrypt_for_use};
use secure_data::kms::StaticDevKeyProvider;

// StaticDevKeyProvider is for development/testing only
let provider = StaticDevKeyProvider::new();

// Encrypt
let plaintext = b"sensitive customer data";
let envelope = encrypt_for_storage(plaintext, "app-data-key", &provider)
    .await
    .expect("encryption must succeed");

// envelope contains:
//   version: "1"
//   algorithm: "AES-256-GCM"
//   key_alias: "app-data-key"
//   wrapped_data_key: [encrypted DEK bytes]
//   nonce: [96-bit random]
//   ciphertext: [AEAD ciphertext]

// Decrypt
let recovered = decrypt_for_use(&envelope, &provider)
    .await
    .expect("decryption must succeed");

assert_eq!(recovered, plaintext);
```

### `EnvelopeEncrypted` Fields

| Field | Type | Description |
|---|---|---|
| `version` | `String` | Envelope format version (currently `"1"`) |
| `algorithm` | `String` | AEAD algorithm (e.g. `"AES-256-GCM"`, `"XChaCha20-Poly1305"`) |
| `key_alias` | `String` | Logical key alias |
| `key_version` | `String` | Specific key version used |
| `wrapped_data_key` | `Vec<u8>` | DEK wrapped by KEK |
| `nonce` | `Vec<u8>` | 96-bit random nonce (unique per encryption) |
| `ciphertext` | `Vec<u8>` | AES-256-GCM ciphertext |
| `aad` | `Vec<u8>` | Additional authenticated data |

The envelope is `Serialize + Deserialize` — store it in your database as JSON.

---

## Key Lifecycle Management

### `KeyRing` — Key Registry

Track key aliases, versions, and lifecycle status:

```rust
use secure_data::keyring::{KeyRing, KeyVersionStatus};

let mut keyring = KeyRing::new();

// Register a new key alias with its initial version
keyring.add_key("customer-data-key".into(), "v1".into());

// Check the active version
let active = keyring.active_version("customer-data-key");
assert_eq!(active, Some("v1"));

// Check version status
let status = keyring.version_status("customer-data-key", "v1");
assert_eq!(status, Some(KeyVersionStatus::Active));
```

### Key Rotation

```rust
use secure_data::keyring::{KeyRing, KeyVersionStatus};

let mut keyring = KeyRing::new();
keyring.add_key("app-key".into(), "v1".into());

// Rotate: v1 becomes DecryptOnly, v2 becomes Active
let new_version = keyring.rotate("app-key").unwrap();
// new_version is auto-generated (e.g., "v2")

assert_eq!(
    keyring.version_status("app-key", "v1"),
    Some(KeyVersionStatus::DecryptOnly) // can still decrypt old data
);
assert_eq!(
    keyring.active_version("app-key"),
    Some(new_version.as_str()) // new data encrypted with this
);

// After all data is re-encrypted, deactivate the old version
keyring.deactivate("app-key", "v1").unwrap();
assert_eq!(
    keyring.version_status("app-key", "v1"),
    Some(KeyVersionStatus::Deactivated)
);
```

### Key Version Status

| Status | Encrypt | Decrypt | Description |
|---|---|---|---|
| `Active` | ✓ | ✓ | Current key for new encryptions |
| `DecryptOnly` | — | ✓ | Old key, can still decrypt existing data |
| `Deactivated` | — | — | Fully retired, unusable |

---

## Re-Encryption During Rotation

When rotating keys, re-encrypt existing data with the new key:

```rust
use secure_data::rotation::re_encrypt;
use secure_data::envelope::{encrypt_for_storage, decrypt_for_use};
use secure_data::kms::StaticDevKeyProvider;

let provider = StaticDevKeyProvider::new();

// Original encryption with old key
let old_envelope = encrypt_for_storage(b"data", "old-key", &provider).await?;

// Re-encrypt with new key (decrypts then encrypts in one step)
let new_envelope = re_encrypt(&old_envelope, "new-key", &provider).await?;

// Verify
let recovered = decrypt_for_use(&new_envelope, &provider).await?;
assert_eq!(recovered, b"data");
assert_eq!(new_envelope.key_alias, "new-key");
```

---

## Secret References

Parse secret references from configuration files:

```rust
use secure_data::config::SecretReference;

// HashiCorp Vault
let vault_ref = SecretReference::parse("vault://kv/prod-db#password").unwrap();
// vault_ref.provider == SecretReferenceProvider::Vault
// vault_ref.path == "kv/prod-db"
// vault_ref.field == Some("password")

// AWS KMS
let kms_ref = SecretReference::parse("kms://alias/my-key").unwrap();
// kms_ref.provider == SecretReferenceProvider::Kms
// kms_ref.path == "alias/my-key"

// Environment variable
let env_ref = SecretReference::parse("env://DATABASE_URL").unwrap();
// env_ref.provider == SecretReferenceProvider::Env
// env_ref.path == "DATABASE_URL"
```

### Resolving Secrets at Runtime

```rust
use secure_data::config::SecretReference;
use secure_data::resolve::resolve_secret;

// Set up environment
std::env::set_var("DB_PASSWORD", "secret-from-env");

let reference = SecretReference::parse("env://DB_PASSWORD").unwrap();
let secret = resolve_secret(&reference).await.unwrap();

assert_eq!(secret.expose_secret(), "secret-from-env");

// For vault:// and kms:// providers, ensure the respective
// features are enabled and the providers are configured
```

---

## KMS Providers

### `StaticDevKeyProvider` — Development Only

```rust
use secure_data::kms::StaticDevKeyProvider;

let provider = StaticDevKeyProvider::new();
// Fixed 32-byte key for "default" alias
// Uses XOR wrapping (NOT production-safe)
// No external dependencies — works offline
```

### HashiCorp Vault Provider (feature: `vault`)

```rust
use secure_data::providers::vault::VaultKeyProvider;

let provider = VaultKeyProvider::new(
    "https://vault.example.com:8200",
    "hvs.your-vault-token",
)?;

// Uses Vault Transit engine:
//   Generate: POST /v1/transit/datakey/plaintext/{alias}
//   Decrypt:  POST /v1/transit/decrypt/{alias}
```

### AWS KMS Provider (feature: `aws-kms`)

```rust
use secure_data::providers::aws_kms::AwsKmsKeyProvider;

// Standard AWS credential chain (env vars, profiles, IMDS)
let provider = AwsKmsKeyProvider::new().await;

// Custom endpoint (e.g., LocalStack for testing)
let provider = AwsKmsKeyProvider::with_endpoint(
    "http://localhost:4566"
).await;

// Uses AWS KMS:
//   Generate: GenerateDataKey (AES_256)
//   Decrypt:  Decrypt
```

---

## Serde Redaction

Use `#[serde(serialize_with = "...")]` to redact fields in your own structs:

```rust
use secure_data::serde::{redact, RedactedField};
use serde::Serialize;

#[derive(Serialize)]
struct UserProfile {
    pub username: String,
    #[serde(serialize_with = "redact")]
    pub ssn: String,             // → "[REDACTED]" in JSON
    pub status: RedactedField,   // → "[REDACTED]" always
}

let profile = UserProfile {
    username: "alice".into(),
    ssn: "123-45-6789".into(),
    status: RedactedField,
};

let json = serde_json::to_string(&profile).unwrap();
// {"username":"alice","ssn":"[REDACTED]","status":"[REDACTED]"}
```

---

## Error Handling

```rust
use secure_data::error::DataError;

// All possible errors:
let err = DataError::KeyNotFound { alias: "unknown".into() };
let err = DataError::KeyDeactivated { alias: "app-key".into(), version: "v1".into() };
let err = DataError::EncryptionFailed { reason: "invalid key length".into() };
let err = DataError::DecryptionFailed { reason: "authentication tag mismatch".into() };
let err = DataError::InvalidNonce { expected: 12, actual: 8 };
let err = DataError::InvalidSecretReference { input: "bad://ref".into() };
let err = DataError::ProviderUnavailable { provider: "vault".into(), reason: "timeout".into() };
let err = DataError::SecretNotFound { reference: "env://MISSING".into() };
```

---

## Password Hashing (feature: `password`)

The `password` module provides Argon2id password hashing and verification with secure defaults.

### Basic Usage

```rust
use secure_data::password::{hash_password, verify_password};
use secure_data::secret::SecretString;

let password = SecretString::new("correct-horse-battery".to_string());

// Hash — returns a PasswordHash in PHC string format ($argon2id$...)
let hash = hash_password(&password).expect("hashing should succeed");

// Persist hash.expose_hash() to your database
let phc_string = hash.expose_hash().to_string();

// Verify — constant-time comparison, returns Ok(true) or Ok(false)
assert!(verify_password(&password, &hash).expect("verify should succeed"));
```

### Security Properties

- **Argon2id** — winner of the Password Hashing Competition; memory-hard, resistant to GPU and side-channel attacks.
- **Random salt** — every call to `hash_password()` generates a unique salt via `OsRng`.
- **Constant-time verification** — `verify_password()` uses the argon2 crate's constant-time comparison.
- **Zeroize on drop** — `PasswordHash` inner value is zeroized when dropped.
- **Redacted output** — `Debug` prints `PasswordHash([REDACTED])`; `Serialize` emits `"[REDACTED]"`.
- **Empty password rejected** — `hash_password()` returns `PasswordError::EmptyPassword` for empty input.

### Custom Hasher

Use the `PasswordHasher` trait for polymorphic or testable code:

```rust
use secure_data::password::{Argon2Hasher, PasswordHasher};
use secure_data::secret::SecretString;

let hasher = Argon2Hasher::default();
let password = SecretString::new("my-password".to_string());
let hash = hasher.hash_password(&password).unwrap();
assert!(hasher.verify_password(&password, &hash).unwrap());
```

---

## Crypto Agility (M25)

The `algorithm` module enables switching encryption algorithms without changing application code — a key ESAPI principle. The algorithm tag is stored in every encrypted envelope so decryption can select the correct primitive even after the system default changes.

### Supported Algorithms

| Algorithm | Enum Variant | Nonce Size | Notes |
|---|---|---|---|
| AES-256-GCM | `CryptoAlgorithm::Aes256Gcm` | 12 bytes | Default; NIST standard |
| XChaCha20-Poly1305 | `CryptoAlgorithm::XChaCha20Poly1305` | 24 bytes | Larger nonce, no nonce-reuse risk |

### Selecting an Algorithm via Policy

```rust
use secure_data::algorithm::{AlgorithmPolicy, CryptoAlgorithm};
use secure_data::envelope::{encrypt_with_policy, decrypt_for_use};
use secure_data::kms::StaticDevKeyProvider;

let provider = StaticDevKeyProvider::new();

// Choose XChaCha20-Poly1305 for new encryptions
let policy = AlgorithmPolicy::prefer(CryptoAlgorithm::XChaCha20Poly1305);
let envelope = encrypt_with_policy(b"secret", "my-key", &provider, &policy)
    .await
    .expect("must succeed");
assert_eq!(envelope.algorithm, "XChaCha20-Poly1305");

// Decryption is automatic — the algorithm is read from the envelope
let plaintext = decrypt_for_use(&envelope, &provider).await.unwrap();
assert_eq!(plaintext, b"secret");
```

### Enforcing Minimum Algorithm Strength

```rust
use secure_data::algorithm::{AlgorithmPolicy, CryptoAlgorithm};

// Require at least XChaCha20 — reject AES-256-GCM
let policy = AlgorithmPolicy::new(
    CryptoAlgorithm::Aes256Gcm,       // preferred
    Some(CryptoAlgorithm::XChaCha20Poly1305), // minimum
);
// This will fail because AES ranks below XChaCha in policy ordering
assert!(policy.validate().is_err());
```

### Backward Compatibility

- `encrypt_for_storage()` continues to use AES-256-GCM by default.
- Old envelopes (created before M25) decrypt transparently — they contain `algorithm: "AES-256-GCM"`.
- The `decrypt_for_use()` function reads the algorithm from the envelope and dispatches automatically.

### Azure Key Vault Provider (feature: `azure-kv`)

For production key management with Azure Key Vault:

```rust
#[cfg(feature = "azure-kv")]
{
    use secure_data::key_vault::{AzureKeyVaultProvider, MockVaultClient};

    // In tests — use MockVaultClient
    let provider = AzureKeyVaultProvider::new(MockVaultClient::new());

    // Key material never leaves the vault — only wrap/unwrap operations.
}
```

---

## Full Integration Example

```rust
use secure_data::envelope::{encrypt_for_storage, decrypt_for_use};
use secure_data::secret::SecretString;
use secure_data::keyring::{KeyRing, KeyVersionStatus};
use secure_data::kms::StaticDevKeyProvider;
use secure_data::config::SecretReference;
use std::sync::Arc;

// Application setup
let provider = Arc::new(StaticDevKeyProvider::new());
let mut keyring = KeyRing::new();
keyring.add_key("user-data-key".into(), "v1".into());

// In a request handler — storing sensitive data
async fn store_user_data(
    data: &[u8],
    provider: &StaticDevKeyProvider,
) -> Result<String, Box<dyn std::error::Error>> {
    // Encrypt before storing
    let envelope = encrypt_for_storage(data, "user-data-key", provider).await?;

    // Serialize envelope to JSON for database storage
    let json = serde_json::to_string(&envelope)?;

    // Store json in your database
    Ok(json)
}

// Later — retrieving sensitive data
async fn load_user_data(
    envelope_json: &str,
    provider: &StaticDevKeyProvider,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let envelope = serde_json::from_str(envelope_json)?;
    let plaintext = decrypt_for_use(&envelope, provider).await?;
    Ok(plaintext)
}

// Configuration with secret references
fn load_config() -> Result<(), Box<dyn std::error::Error>> {
    let db_ref = SecretReference::parse("env://DATABASE_URL")?;
    let api_ref = SecretReference::parse("vault://kv/api-keys#stripe")?;
    // Resolve at startup, store as SecretString
    Ok(())
}
```

---

## Feature Flags

| Feature | Adds | Use When |
|---|---|---|
| `vault` | `VaultKeyProvider`, `reqwest` | Using HashiCorp Vault Transit |
| `aws-kms` | `AwsKmsKeyProvider`, `aws-sdk-kms` | Using AWS KMS |
| `fips` | `aws-lc-rs` AEAD backend | FIPS 140-2/3 compliance required |
| `password` | `Argon2Hasher`, `argon2` | Password hashing with Argon2id |

All features are off by default. Enable only what you need:

```sh
cargo build -p sunlit_secure_data --features vault,aws-kms
```

---

## API Reference

| Type | Module | Description |
|---|---|---|
| `SecretString` | `secret` | Redacted string wrapper |
| `SecretBytes` | `secret` | Redacted bytes wrapper |
| `ApiToken` | `secret` | API token wrapper |
| `DbPassword` | `secret` | Database password wrapper |
| `SigningKeyRef` | `secret` | Signing key reference wrapper |
| `ReadOnce<T>` | `memory` | Single-use value wrapper |
| `EnvelopeEncrypted` | `envelope` | Envelope encryption output |
| `encrypt_for_storage()` | `envelope` | Encrypt plaintext → envelope |
| `decrypt_for_use()` | `envelope` | Decrypt envelope → plaintext |
| `KeyRing` | `keyring` | Key alias/version registry |
| `KeyVersionStatus` | `keyring` | Active / DecryptOnly / Deactivated |
| `KeyVersionEntry` | `keyring` | Version metadata |
| `KeyProvider` | `kms` | Sealed KMS trait |
| `StaticDevKeyProvider` | `kms` | Dev/test-only key provider |
| `VaultKeyProvider` | `providers::vault` | HashiCorp Vault Transit (feature `vault`) |
| `AwsKmsKeyProvider` | `providers::aws_kms` | AWS KMS (feature `aws-kms`) |
| `SecretReference` | `config` | Parsed secret URI |
| `SecretReferenceProvider` | `config` | Vault / Kms / Env |
| `resolve_secret()` | `resolve` | Runtime secret resolution |
| `RotationPlan` | `rotation` | Key rotation plan |
| `re_encrypt()` | `rotation` | Re-encrypt with new key |
| `redact()` | `serde` | Serde redaction serializer |
| `RedactedField` | `serde` | Always-redacted marker type |
| `DataError` | `error` | Data protection error enum |
| `PasswordHash` | `password` | Redacted password hash (PHC format, feature `password`) |
| `PasswordHasher` | `password` | Password hashing trait (feature `password`) |
| `Argon2Hasher` | `password` | Argon2id hasher (feature `password`) |
| `hash_password()` | `password` | Hash a password with Argon2id (feature `password`) |
| `verify_password()` | `password` | Verify a password against a hash (feature `password`) |
| `PasswordError` | `password` | Password hashing error enum (feature `password`) |
