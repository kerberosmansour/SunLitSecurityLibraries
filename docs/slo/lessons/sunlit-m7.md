# Lessons Learned — Milestone 7: `secure_data` — Data Protection & Secrets Management (OWASP C8)

**Date**: 2026-04-06
**Milestone**: 7 — `secure_data`
**Status**: done

---

## What We Built

A data-protection library implementing OWASP C8, providing:

| Module | Contents |
|---|---|
| `secret` | `SecretString`, `SecretBytes`, `ApiToken`, `DbPassword`, `SigningKeyRef` — typed wrappers using `zeroize::Zeroizing`; no `Debug`/`Display` on secret values; custom `Serialize` emits `"[REDACTED]"` |
| `kms` | `KeyProvider` sealed trait (native `async fn`), `StaticDevKeyProvider` for tests (XOR-based DEK wrapping, dev/test only) |
| `envelope` | `encrypt_for_storage()`, `decrypt_for_use()`, `EnvelopeEncrypted` struct with `#[must_use]`; AES-256-GCM via `aes-gcm` crate; random nonce via `rand::rngs::OsRng`; AAD built from version/algorithm/alias/key_version metadata |
| `keyring` | `KeyRing` with per-alias version list; `KeyVersionStatus` (`#[non_exhaustive]`): Active, DecryptOnly, Deactivated; `rotate()` demotes current active → DecryptOnly and creates new Active version |
| `rotation` | `RotationPlan`, `re_encrypt()` — decrypt old envelope + re-encrypt under new key; enables dual-read migration |
| `config` | `SecretReference` with `parse()` for `vault://`, `kms://`, `env://` schemes; `SecretReferenceProvider` enum |
| `serde` | `redact()` serializer function for `#[serde(serialize_with)]`; `RedactedField` marker type |
| `memory` | `ReadOnce<T>` wrapper: `!Clone`, `!Copy`, `!Sync` (via `Cell<bool>`); zeroizes on drop; `Zeroizing<T>` re-export |
| `error` | `DataError` with 11 variants covering all failure modes |

**33 tests** passing across 5 test files.

---

## Key Design Decisions

### 1. Native `async fn in trait` without `async-trait` crate

The `KeyProvider` trait uses native `async fn` (Rust 1.75+), which avoids the `async-trait` crate (explicitly forbidden). The sealed trait pattern (`mod private { pub trait Sealed {} }`) prevents external implementations that could bypass internal invariants.

**Trade-off**: The futures are not automatically `Send`. Since `StaticDevKeyProvider` is the only implementation and tests are single-threaded `#[tokio::test]`, this is acceptable. A production KMS adapter should explicitly annotate `+ Send` on the future return types.

### 2. `Zeroizing<Vec<u8>>` and `Zeroizing<String>` over `secrecy::SecretBox`

While the runbook mentions `secrecy::SecretBox`, `Zeroizing<T>` from the `zeroize` crate directly provides the same guarantee (memory is zeroed on drop, clearing is not optimized away) with simpler integration. We include `secrecy` as a dependency for the `serde` feature but use `Zeroizing<T>` as the core primitive.

### 3. Sealed `KeyProvider` trait

The `mod private { pub trait Sealed {} }` pattern prevents external crates from implementing `KeyProvider`, ensuring the internal invariants of the envelope format are upheld. Real backend adapters (KMS, Vault) should be added within this crate as feature-gated modules.

### 4. `Cell<bool>` makes `ReadOnce<T>` `!Sync`

`Cell<T>` does not implement `Sync`, so `ReadOnce<T>` is `!Sync` automatically without needing `PhantomData<*mut ()>` (which would require `unsafe impl Send`). Since the crate has `#![forbid(unsafe_code)]`, this is the correct approach.

### 5. AAD binds metadata to ciphertext

The AAD is constructed from `version`, `algorithm`, `key_alias`, and `key_version`. Any tampering with the envelope metadata (e.g., changing `key_alias` to redirect to a different key) will cause AEAD authentication to fail, preventing key-confusion attacks.

### 6. FIPS feature flag is declared but `aws-lc-rs` is optional

The `fips` feature gates `aws-lc-rs` as an optional dependency. The `AeadBackend` abstraction is deferred — the current implementation always uses `aes-gcm` (RustCrypto). A future milestone can add the FIPS backend by implementing the abstraction and selecting it when `cfg(feature = "fips")`.

---

## Gotchas

1. **`#![deny(missing_docs)]`** requires doc comments on all public struct fields, not just types and functions. Enum variant fields (struct-style) also require docs.

2. **`#![forbid(unsafe_code)]`** prevents `unsafe impl Send`**. Use `Cell<T>` to achieve `!Sync` without unsafe. The `Send` impl is derived automatically when all fields are `Send`.

3. **Real Vault/KMS adapters are feature-gated stubs** — the `StaticDevKeyProvider` uses XOR-based "wrapping" which is not cryptographically secure. Never use in production.

4. **Deferred features** (document for future milestones):
   - `aws-lc-rs` FIPS backend integration
   - Field-level ORM encryption helpers
   - TLS profile helpers
   - JWT/PASETO signing key handles
   - Secret lease renewal hooks for Vault
   - KMS and Vault client adapters

5. **`thiserror` version**: The workspace uses `thiserror` v1 in some crates; `secure_data` pulls in both v1 and v2 depending on transitive dependencies. This is fine — they coexist.

---

## Test Coverage

- **8 BDD secret tests** (`sunlit_data_secrets.rs`): no-debug-leak for all types, zeroize-on-drop, serde redaction, expose_secret access
- **5 BDD envelope tests** (`sunlit_data_envelope.rs`): roundtrip, metadata fields, unique nonces, tampered ciphertext rejected, tampered AAD rejected
- **5 BDD rotation tests** (`sunlit_data_rotation.rs`): rotate adds version, decrypt old version, re-encrypt to new version, deactivated key, cannot deactivate last version
- **7 BDD leakage tests** (`sunlit_data_leakage.rs`): absent from JSON, absent from panic, absent from format, vault ref parsed, kms ref parsed, env ref parsed, invalid ref rejected
- **6 E2E tests** (`e2e_sunlit_m7.rs`): encrypt-decrypt roundtrip, key rotation dual-read, no debug leak, no serde leak, tampered data rejected, secret reference resolution

---

## What the Next Milestone Needs From This One

- `StaticDevKeyProvider` — wire into `secure_reference_service` state for dev/test
- `encrypt_for_storage` / `decrypt_for_use` — demonstrate in reference service routes
- `SecretString` / `SecretBytes` — use as DTO field types in reference service
- `SecretReference::parse()` — use in `SecurityConfig` validation at startup
- `KeyRing` — include in shared app state for key lifecycle demonstration
