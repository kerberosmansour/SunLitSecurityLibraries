# Lessons Learned — Milestone 13: Real Key Provider Integrations

**Date:** 2026-04-06  
**Milestone:** M13 — Real key provider integrations

---

## 1. Sealed trait pattern works well for provider extensibility

**What happened:** Adding `VaultKeyProvider` and `AwsKmsKeyProvider` inside the `secure_data` crate was straightforward because the `KeyProvider` trait is sealed. Each new provider just needed a `Sealed` impl and the two trait methods.

**Apply going forward:** This pattern should be reused for any future providers (Azure Key Vault, GCP KMS). The sealed trait prevents external implementations from breaking internal invariants while allowing controlled extension within the crate.

---

## 2. Mock HTTP servers for Vault tests use raw TCP

**What happened:** The Vault tests use a simple `TcpListener`-based mock server that returns pre-configured HTTP responses. This avoids adding a mock server dependency while providing deterministic test behavior.

**Apply going forward:** This pattern works for any HTTP API mock where you control the exact response format. For more complex scenarios (multi-request flows, state tracking), consider a proper mock framework.

---

## 3. AWS SDK testing requires custom endpoint URL

**What happened:** `AwsKmsKeyProvider::with_endpoint()` was needed to redirect the AWS SDK to a local mock server. The standard `new()` constructor resolves credentials from the environment, which fails in test environments.

**Apply going forward:** Always provide a `with_endpoint()` or `with_client()` constructor for cloud SDK wrappers to enable testability without real cloud credentials.

---

## 4. `env://` resolution is lazy by design

**What happened:** `resolve_secret()` reads environment variables at call time, not at `SecretReference::parse()` time. This is intentional — secrets may be injected after config parsing (e.g., by a container orchestrator).

**Apply going forward:** Never cache resolved secret values across calls unless the caller explicitly requests it. Secrets may rotate.

---

## 5. `kms://` is not resolvable to a string secret

**Design choice:** KMS key aliases identify encryption keys, not string secrets. `resolve_secret()` returns `DataError::InvalidSecretReference` for `kms://` references. KMS keys are used via `KeyProvider::generate_data_key()` / `unwrap_data_key()`, not via string resolution.

---

## 6. Feature flags must be off by default

**Design choice:** Both `vault` and `aws-kms` features are optional. The workspace builds and all non-feature-gated tests pass without any cloud SDKs. This keeps the default build fast and dependency-light.

---

## 7. Error variants for providers already existed

**What happened:** `ProviderUnavailable`, `ProviderAuthError`, and `SecretNotFound` variants were already defined in `error.rs` from the initial crate structure. No new error variants were needed.

**Apply going forward:** Check existing error types before adding new ones. The `#[non_exhaustive]` attribute on `DataError` allows future additions without breaking changes.

---

## Rules for the next milestone

- The `Authenticator` sealed trait in `secure_identity` follows the same pattern as `KeyProvider` — new implementations go inside the crate
- Constant-time comparison for API keys must use `ring` or `subtle` crate — never `==` on secret bytes
- JWKS cache TTL must be configurable and default to a reasonable value (e.g., 5 minutes)
