# Completion Summary — sunlit-owasp Milestone 25

## Goal completed
- Crypto agility in `secure_data`: support for multiple encryption algorithms (AES-256-GCM and XChaCha20-Poly1305), algorithm policy enforcement, algorithm tag stored in encrypted envelopes for transparent migration, and Azure Key Vault provider behind feature flag

## Files changed
- `crates/secure_data/src/algorithm.rs` — NEW: `CryptoAlgorithm` enum, `AlgorithmPolicy` type
- `crates/secure_data/src/envelope.rs` — Extended to support algorithm selection, added `encrypt_with_policy()`, added AAD recomputation during decryption
- `crates/secure_data/src/key_vault.rs` — NEW: `VaultClient` trait, `MockVaultClient`, `AzureKeyVaultProvider`
- `crates/secure_data/src/error.rs` — Added `UnsupportedAlgorithm` and `AlgorithmBelowPolicyMinimum` variants
- `crates/secure_data/src/lib.rs` — Added `pub mod algorithm;` and `pub mod key_vault;` (feature-gated)
- `crates/secure_data/Cargo.toml` — Added `chacha20poly1305` dependency, `azure-kv` feature flag

## Tests added
- `crates/secure_data/tests/sunlit_owasp_agility.rs` — 10 BDD tests covering algorithm selection, policy enforcement, key versioning, backward compatibility
- `crates/secure_data/tests/sunlit_owasp_keyvault.rs` — 3 BDD tests covering Azure KV wrap/unwrap and vault unavailability

## Runtime validations added
- `crates/secure_data/tests/e2e_sunlit_owasp_m25.rs` — 5 E2E tests: AES roundtrip, XChaCha roundtrip, old envelope backward compat, key version rotation, algorithm downgrade prevention

## Compatibility checks performed
- All existing envelope encryption tests still pass (5 tests in `sunlit_data_envelope.rs`)
- All existing E2E tests pass (`e2e_sunlit_m7.rs`, `e2e_sunlit_imp_m13.rs`)
- `encrypt_for_storage()` backward compatible — defaults to AES-256-GCM
- `KeyProvider` trait unchanged
- `InMemoryKeyRing` unchanged
- Property-based crypto tests still pass
- Password hashing (M20) unaffected

## Documentation updated
- `ARCHITECTURE.md` — Updated `secure_data` section with crypto agility, key versioning, Azure Key Vault
- `README.md` — Updated `secure_data` feature flags table and usage example with crypto agility
- `docs/dev-guide/secure-data.md` — Added crypto agility section with algorithm selection, policy enforcement, backward compatibility, and Azure KV usage; updated `EnvelopeEncrypted` fields table

## .gitignore changes
- No new patterns needed

## Test artifact cleanup verified
- All tests are stateless/in-memory — no file output
- `git status` is clean after test runs

## Deferred follow-ups
- Real Azure Key Vault integration test against Azure sandbox
- Property-based testing for XChaCha20-Poly1305 roundtrip
- Additional algorithms (e.g., AES-128-GCM) could be added to `CryptoAlgorithm` enum in the future

## Known non-blocking limitations
- `chacha20poly1305` has 36 lines in `cargo tree` output (above the 20-line guidance), but most dependencies are shared with `aes-gcm` (RustCrypto ecosystem)
- `AzureKeyVaultProvider` tested only with `MockVaultClient` — real Azure integration deferred
