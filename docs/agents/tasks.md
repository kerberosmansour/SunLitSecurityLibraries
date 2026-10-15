# SunLit Rust consumer task contracts

These tasks target published **0.4.0**. Use an existing supported Rust application,
review each crate's features and framework compatibility, and resolve a lockfile
without builds before complete OSV/provenance admission. Preserve cargo-vet and
stricter consumer policy. The [published usage reference](../../skills/sunlit-rust-security/references/usage.md)
links every crate and versioned API. Examples are focused fragments, not complete
services. All tasks use the optional [feedback workflow](feedback.md).

## 1. Add deny-by-default authorization

Package: `secure_authz = "=0.4.0"`; Axum is enabled by default.
Use the reference's DefaultPolicyEngine/DefaultAuthorizer example with an
application-authenticated Subject. An empty policy must deny. Add a specific allow
rule, then test permitted actions, unknown actions and cross-tenant denial.
For middleware, read the installed version's AuthzLayer contract and initialize
identity before authorization. A request body's roles/tenant cannot establish
identity. On denial, inspect trusted subject/resource/action data and policy order;
do not add a blanket allow. Evidence:
[published denial tests](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/v0.4.0/crates/secure_authz/tests/sunlit_authz_deny_default.rs).

## 2. Encrypt stored state and reject tampering

Package: `secure_data = "=0.4.0"`; select the production KMS feature deliberately.
Use the reference's encrypt_for_storage/decrypt_for_use round-trip only with
synthetic data and the explicitly development-only StaticDevKeyProvider.
Verify ciphertext tamper and wrong-key rejection as well as round-trip success.
Production key custody, authorization, rotation and recovery remain application
responsibilities; neither this example nor the mobile bridge proves device security.
On failure, check key identity, provider configuration and envelope compatibility;
never fall back to plaintext. Evidence:
[published envelope tests](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/v0.4.0/crates/secure_data/tests/sunlit_data_envelope.rs).

## 3. Validate Actix-web request bodies

Use `secure_boundary = { version = "=0.4.0", default-features = false, features = ["actix-web"] }`
in an admitted Actix-web 4 application. Define a DTO with serde deny_unknown_fields
and implement SecureValidate syntax/semantic checks before using SecureJson in the
handler. Copy the complete bounded harness from the
[published Actix extractor tests](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/v0.4.0/crates/secure_boundary/tests/sg_gate_a_actix_extract.rs).
Minimal handler shape from that harness:

```rust
async fn handler(body: secure_boundary::SecureJson<CreateItem>) -> actix_web::HttpResponse {
    let _validated = body.into_inner();
    actix_web::HttpResponse::Ok().finish()
}
```

CreateItem and its validation implementation are required; this fragment alone is
not compilable. Verify valid input, wrong content type, malformed JSON, oversized
body, depth, field count and semantic rejection. Apply per-route RequestLimits.
Validation is not authentication/authorization, and middleware ordering must match
the actual application. Fix DTO/limit mismatches instead of using an unvalidated
extractor to bypass a rejection.

## 4. Select an HMAC-only JWT profile

In a service that deliberately supports HMAC rather than asymmetric JWT/JWKS:

```toml
secure_identity = { version = "=0.4.0", default-features = false, features = ["jwt-hmac"] }
```

Install the published HMAC provider at startup with
`secure_identity::jwt_hmac::install_default_provider()` and handle failure.
Use trusted issuer/audience and suitable secret custody; do not copy test keys.
Cargo feature unification can re-enable asymmetric support through another
workspace member: inspect `cargo tree -e features -i secure_identity` and
`cargo tree -i rsa` in the admitted full application. An absent rsa package is an
expected outcome for the reduced graph, not a universal workspace guarantee.
Verify valid HS256, bad signature, wrong issuer/audience, expiration, disallowed
algorithms and key-size bounds using the
[published HMAC tests](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/v0.4.0/crates/secure_identity/tests/jwt_hmac_profile.rs).
This profile is unsuitable when asymmetric JWT, SSH keys, JWKS or OIDC are needed.
Do not remove required verification to resolve an integration failure.

## 5. Emit a classified security event without leaking secrets

Packages: `security_events = "=0.4.0"` and `security_core = "=0.4.0"`.
Use the reference's SecurityEvent/emit_security_event example with synthetic values.
Configure the actual sink/redaction policy and test a synthetic secret canary never
appears in emitted output. Check outcome/severity and missing/invalid-field behavior.
The emission API uses application tracing; it does not report to SunLit or
implicitly produce HMAC-signed evidence. Signing, retention and sink access require
explicit application configuration. On leakage, stop export and correct field
classification; do not log the raw input for diagnosis. Evidence:
[published emission implementation and doctest](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/v0.4.0/crates/security_events/src/emit.rs).
