# Lessons Learned — sunlit-owasp Milestone 25

## What changed
- Added `secure_data::algorithm` module with `CryptoAlgorithm` enum (`Aes256Gcm`, `XChaCha20Poly1305`) and `AlgorithmPolicy` for algorithm selection/enforcement
- Extended `EnvelopeEncrypted` to dispatch encryption/decryption based on the `algorithm` field stored in the envelope
- Added `encrypt_with_policy()` for algorithm-aware encryption; `encrypt_for_storage()` remains backward compatible (defaults to AES-256-GCM)
- Added AAD recomputation during decryption to detect metadata field tampering
- Added `secure_data::key_vault` module with `VaultClient` trait, `MockVaultClient`, and `AzureKeyVaultProvider` behind `azure-kv` feature flag
- Added new `DataError` variants: `UnsupportedAlgorithm`, `AlgorithmBelowPolicyMinimum`
- Added `chacha20poly1305` dependency for XChaCha20-Poly1305 support

## Design decisions and why
- `CryptoAlgorithm` enum stores canonical string identifiers in envelopes — ensures decryption can dispatch even after system default changes
- `AlgorithmPolicy` uses a rank-based ordering for downgrade prevention — simple and extensible without complex policy languages
- AAD is recomputed from envelope header fields during decryption, not just read from the stored `aad` field — catches metadata tampering (key_version, algorithm, key_alias)
- `VaultClient` trait is open (not sealed) for extensibility — real Azure SDK implementations can be plugged in
- `AzureKeyVaultProvider` implements `KeyProvider` (sealed) — keeps the key provider abstraction consistent while allowing vault-specific client implementations
- Used `#[derive(Default)]` with `#[default]` attribute on `Aes256Gcm` variant per clippy recommendation

## Mistakes made
- Initial test `test_unknown_key_version_handled` failed because the StaticDevKeyProvider ignores version and stored AAD was not recomputed
- Forgot to remove `ALGORITHM` and `NONCE_LEN` constants after refactoring, though they were correctly addressed

## Root causes
- The original decrypt path used stored AAD directly without recomputation, which meant metadata field tampering wasn't detected
- StaticDevKeyProvider intentionally ignores version for simplicity, so testable detection of version tampering required the AAD recomputation fix

## What was harder than expected
- Getting the AAD integrity check right — the original design stored AAD in the envelope and used it directly during decryption, which meant changing metadata fields (like key_version) didn't trigger failures

## Naming conventions established
- Modules: `algorithm`, `key_vault`
- Types: `CryptoAlgorithm`, `AlgorithmPolicy`, `AzureKeyVaultProvider`, `VaultClient`, `MockVaultClient`
- Functions: `encrypt_with_policy()`, `from_envelope_str()`, `as_str()`
- Test files: `sunlit_owasp_agility.rs`, `sunlit_owasp_keyvault.rs`, `e2e_sunlit_owasp_m25.rs`

## Test patterns that worked well
- Feature-gated Azure KV tests (`#[cfg(feature = "azure-kv")]`) to avoid compilation overhead
- Tampered-field tests for AAD integrity verification
- Policy violation tests with contradictory preferred/minimum algorithms

## Missing tests that should exist now
- Integration test with real Azure Key Vault sandbox
- Property-based testing for encrypt/decrypt roundtrip across both algorithms
- Benchmark comparison of AES-256-GCM vs XChaCha20-Poly1305 throughput

## Rules for the next milestone
- M26 focuses on documentation only — do not change any function signatures or behavior
- Ensure all M18–M25 public APIs have `# Examples` doc sections
- Verify convenience free functions exist for all stateless operations

## Template improvements suggested
- None — the template worked well for this milestone
