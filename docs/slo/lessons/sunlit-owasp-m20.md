# Lessons Learned — sunlit-owasp Milestone 20

## What changed
- Added `password.rs` module to `secure_data` with Argon2id password hashing and verification
- `PasswordHash` type wrapping PHC string format, redacted in Debug/Serialize, zeroized on drop
- `PasswordHasher` trait for algorithm extensibility with `Argon2Hasher` default implementation
- `hash_password()` and `verify_password()` free functions as primary API
- `PasswordError` error enum with `EmptyPassword`, `HashingFailed`, `InvalidHashFormat` variants
- Feature-gated behind `password` Cargo feature (`argon2` optional dependency)
- 7 doc-tests covering all public APIs
- 12 BDD tests, 4 E2E runtime validation tests

## Design decisions and why
- **Feature-gated `password` module** — follows existing crate pattern (`vault`, `aws-kms`, `fips`) to keep default builds lean, per the design principle "Feature-flag gating for external deps"
- **Free functions as primary API** — `hash_password()` and `verify_password()` are the main entry points, matching M19 lesson and the Rust-idiomatic API principle. Trait impl exists for polymorphic contexts.
- **`PasswordHash` as opaque wrapper** — `new()` is `pub(crate)` to prevent construction from arbitrary strings. Only `expose_hash()` gives access. This makes it impossible to accidentally store plaintext as a "hash".
- **Argon2id as sole default** — the runbook scopes bcrypt/scrypt to future feature flags. Argon2id is the OWASP-recommended algorithm (2024 guidelines).
- **`thiserror` v1 for `PasswordError`** — the crate already uses thiserror v1; adding v2 would require a refactor outside scope. Consistent with existing `DataError` in the same crate.
- **Separate `PasswordError` instead of extending `DataError`** — `error.rs` was not in the allowed-files list, and password errors are semantically distinct from encryption errors.
- **`Zeroizing<String>` for inner hash storage** — follows the existing `SecretString` pattern in `secret.rs`.
- **Constant-time verification** — delegated to the `argon2` crate's `PasswordVerifier` trait which uses `subtle::ConstantTimeEq` internally.

## Mistakes made
- Initial module-level `//!` docs used bare intra-doc links (`[`hash_password()`]`) which failed to resolve because rustdoc processes `//!` docs in the parent module's scope. Fixed by using fully qualified paths (`[`hash_password()`](crate::password::hash_password)`).

## Root causes
- Intra-doc link resolution scope: `//!` docs in a module file are rendered as the parent module's context in rustdoc, so unqualified names from the child module are out of scope.

## What was harder than expected
- Nothing significant. The `argon2` crate's API is clean and well-documented. The RustCrypto password-hash ecosystem provides good abstractions.

## Naming conventions established
- Module name: `password.rs` (matches the capability)
- Error type: `PasswordError` (module-local, not added to `DataError`)
- Hasher type: `Argon2Hasher` (algorithm-prefixed, not generic `DefaultHasher`)
- Wrapper type: `PasswordHash` (matches the domain concept)
- Free functions: `hash_password()`, `verify_password()` (verb pattern)

## Test patterns that worked well
- Timing consistency test with warm-up iterations and generous bounds (20ms tolerance)
- Cross-verification between free functions and trait impl (both directions)
- Debug/JSON redaction assertions with exact string matching
- Hash uniqueness via two calls with same input

## Missing tests that should exist now
- Property-based tests: all non-empty strings hash successfully
- Fuzz target for `verify_password()` with random PHC strings
- Benchmark comparing Argon2id hash time across parameter configurations

## Rules for the next milestone
- M21 (browser security headers) introduces `tower-http` — verify it composes with existing middleware stack
- CORS deny-all default must be verified with real HTTP requests, not just unit tests
- CSP nonce generation needs careful scope — per-request, not per-connection

## Template improvements suggested
- None
