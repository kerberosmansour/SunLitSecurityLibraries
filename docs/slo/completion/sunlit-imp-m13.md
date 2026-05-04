# Completion Summary — sunlit-imp Milestone 13

## Goal completed
- HashiCorp Vault Transit key provider (`VaultKeyProvider`) for real envelope encryption
- AWS KMS key provider (`AwsKmsKeyProvider`) using `aws-sdk-kms`
- `resolve_secret()` function for `SecretReference` resolution (`env://`, `vault://`)
- All cloud providers behind Cargo feature flags (`vault`, `aws-kms`) — off by default

## Files changed
- `crates/secure_data/src/providers/mod.rs` — module declarations for vault, aws_kms
- `crates/secure_data/src/providers/vault.rs` — `VaultKeyProvider` + `fetch_vault_kv_secret()`
- `crates/secure_data/src/providers/aws_kms.rs` — `AwsKmsKeyProvider`
- `crates/secure_data/src/resolve.rs` — `resolve_secret()` function
- `crates/secure_data/src/kms.rs` — `Sealed` impl for new providers
- `crates/secure_data/src/lib.rs` — module declarations and re-exports
- `crates/secure_data/src/error.rs` — error variants for provider failures (already existed)
- `crates/secure_data/Cargo.toml` — feature-gated dependencies

## Tests added
- `crates/secure_data/tests/sunlit_imp_vault.rs` — 5 BDD tests (generate, unwrap, unavailable, auth error, roundtrip)
- `crates/secure_data/tests/sunlit_imp_aws_kms.rs` — 3 BDD tests (generate, unwrap, unavailable)
- `crates/secure_data/tests/sunlit_imp_resolve.rs` — 4-5 BDD tests (env happy, env missing, kms unsupported, vault happy, vault disabled)

## Runtime validations added
- `crates/secure_data/tests/e2e_sunlit_imp_m13.rs` — 6 E2E tests (backward compat, envelope roundtrip, env resolution, error variants, parsing)

## Compatibility checks performed
- `StaticDevKeyProvider` unchanged — all existing tests pass
- `EnvelopeEncrypted` struct unchanged
- `encrypt_for_storage()` / `decrypt_for_use()` signatures unchanged
- All existing envelope, leakage, rotation, secrets, and property tests pass
- Workspace builds without any feature flags enabled
- `cargo clippy --workspace --all-targets -- -D warnings` passes

## Documentation updated
- `ARCHITECTURE.md` — Updated Key Provider Abstraction section with VaultKeyProvider and AwsKmsKeyProvider descriptions; added Secret Resolution section
- `README.md` — Added feature flags table for secure_data; updated usage example comment

## .gitignore changes
- No new patterns needed (no new generated files)

## Test artifact cleanup verified
- All tests use in-memory mocks or ephemeral TcpListeners — no disk artifacts
- `git status` clean after test run

## Deferred follow-ups
- Azure Key Vault provider (can follow same pattern)
- Persistent `KeyRingStore` for key metadata
- JWKS fetch for `secure_identity` (M14)

## Known non-blocking limitations
- AWS KMS tests use mock TCP servers, not real LocalStack — real integration requires separate CI setup
- `kms://` references return `InvalidSecretReference` from `resolve_secret()` since KMS keys are not string secrets
