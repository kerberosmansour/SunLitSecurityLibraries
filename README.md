# SunLit Security Libraries

A production-grade Cargo workspace of Rust security crates and reference
services implementing [OWASP Proactive Controls](https://owasp.org/www-project-proactive-controls/)
C1/C2/C4/C5/C6/C7/C8/C9/C10 and OWASP MASVS-aligned controls for services
targeting critical infrastructure.

> **Status**: active development, pre-1.0. Core milestones are complete; the
> detailed runbook history lives in [`docs/slo/`](docs/slo/README.md).
>
> **License**: [MIT OR Apache-2.0](LICENSE). **Security reports**: use the
> private process in [SECURITY.md](SECURITY.md), not a public issue.

---

## Security Requirements Overview

SunLit is built threat-model-first. Before any code is written, a formal STRIDE analysis defines what adversaries, attack vectors, and security invariants every crate must address.

The threat model ([`THREAT_MODEL.md`](./THREAT_MODEL.md)) covers:

| STRIDE Category | Threats Documented | Primary Controls |
|---|---|---|
| **Spoofing** | Token forgery, IdP spoofing, mTLS mis-issuance | `secure_identity`, `security_core` |
| **Tampering** | Audit log tampering, event injection, dependency poisoning | `security_events`, `secure_data` |
| **Repudiation** | Action denial, clock skew, audit gap | `security_events` |
| **Information Disclosure** | Error leakage, secret in logs, side-channels | `secure_errors`, `secure_data`, `security_events` |
| **Denial of Service** | JSON bombs, regex DoS, resource exhaustion | `secure_boundary`, `security_events` |
| **Elevation of Privilege** | Authz bypass, tenant escape, IDOR, supply chain | `secure_authz`, `secure_boundary` |

Compliance mappings: **NIST 800-53** (AC, AU, IA, SC, SI), **IEC 62443**, **SOC 2 Type II**, and an evidence-backed **ANSSI Rust Secure Coding Guidelines** mapping for French-market and IEC 62443-4-1 SD-3 audits.

---

## Crates

| Crate | OWASP Control | Purpose |
|---|---|---|
| `security_core` | C1 foundation | Shared types, ID newtypes, `IdentitySource` trait |
| `secure_errors` | C10 | Centralized error handling, no internal detail leakage |
| `security_events` | C9 | Security telemetry, classification-driven redaction, per-event HMAC sealing, event correlation, log-injection prevention, AppSensor detection points, NDJSON/tracing/file/batched sinks |
| `secure_boundary` | C5/C8 | Input validation, axum extractors, size/depth/field limits, HTML sanitization, browser security headers, CORS, Fetch Metadata |
| `secure_output` | C4 | Context-aware output encoding, security headers |
| `secure_identity` | C6, MASVS-AUTH | Pluggable authentication (one `IdentitySource` implementation), biometric auth validation, step-up auth |
| `secure_device_trust` | C6/C7, MASVS-AUTH | Native-client device trust decisions: bootstrap identity, client type/platform, attestation mode, trust tiers |
| `secure_authz` | C7 | Deny-by-default authorization, identity-agnostic policy engine |
| `secure_data` | C2/C7/C8, MASVS-STORAGE | Secret management, envelope encryption, crypto agility, password hashing (Argon2id), FIPS readiness, mobile secure storage |
| `secure_network` | MASVS-NETWORK | TLS policy validation, certificate pinning (SPKI SHA-256), cleartext traffic detection |
| `secure_resilience` | C10 | Runtime integrity signals, timeout budgeting, and resilience helpers |
| `secure_privacy` | C8 | Data classification handling, consent, retention, redaction, and pseudonymization |
| `secure_reference_service` | integration | Reference axum service with resilience patterns |
| `secure_smoke_service` | smoke-test | 54-route security smoke-test service for DAST scanning (including 15 mobile MASVS routes) |

The libraries are packaged as separate crates so applications can pull only the
control surface they need. The reference and smoke services are not intended
for crates.io publication.

### Cargo package and import names

The current `Cargo.toml` manifests use unprefixed package names. Each published
package name matches its Rust import name exactly, so consumers should use the
same identifier in `[dependencies]`, `cargo add`, and `use` paths.

| Cargo package | Rust import | crates.io |
|---|---|---|
| `security_core` | `security_core` | published |
| `security_events` | `security_events` | published |
| `secure_errors` | `secure_errors` | published |
| `secure_boundary` | `secure_boundary` | published |
| `secure_output` | `secure_output` | published |
| `secure_identity` | `secure_identity` | published |
| `secure_device_trust` | `secure_device_trust` | published |
| `secure_authz` | `secure_authz` | published |
| `secure_data` | `secure_data` | published |
| `secure_network` | `secure_network` | published |
| `secure_resilience` | `secure_resilience` | published |
| `secure_privacy` | `secure_privacy` | published |
| `secure_reference_service` | `secure_reference_service` | private workspace crate |
| `secure_smoke_service` | `secure_smoke_service` | private workspace crate |

```bash
cargo add secure_data --features password
cargo add secure_authz --features axum
```

Release packaging and signing details live in
[`docs/dev-guide/release-process.md`](docs/dev-guide/release-process.md).

### Planned: Native Client Zero-Trust Access

The sibling `ZeroTrustAuth` repository is the guinea-pig experiment for native
desktop/mobile client access before this becomes a supported library capability.
The intended extraction path is:

- new `secure_device_trust` crate for bootstrap certificate validation, device
  attestation evidence, CSR validation, short-lived session certificate issuance
  policy, refresh windows, revocation hooks, and release/test trust profiles.
- `secure_identity` integration for the passwordless step after mTLS, including
  WebAuthn/passkey challenge generation, native deep-link challenge binding,
  and user-session binding to the mTLS client certificate.
- `secure_authz` integration for deny-by-default policy predicates over device
  trust tier, platform, attestation freshness, session certificate status, and
  release channel.
- `secure_network` helpers for mTLS client identity extraction, gateway header
  hardening, certificate-chain policy, and SPKI pinning at native-client edges.

The production version must use per-installation or per-device bootstrap keys
where possible, HSM/KMS-backed CA operations, token binding to the mTLS client
certificate, and platform attestation evidence where the OS supports it.

The production milestone plan lives in
[`docs/slo/future/RUNBOOK-native-device-trust.md`](docs/slo/future/RUNBOOK-native-device-trust.md).

### `secure_data` Feature Flags

| Feature | Dependency | Purpose |
|---|---|---|
| `vault` | `reqwest` | HashiCorp Vault Transit key provider + KV secret resolution |
| `aws-kms` | `aws-sdk-kms`, `aws-config` | AWS KMS `GenerateDataKey`/`Decrypt` key provider |
| `fips` | `aws-lc-rs` | FIPS 140-2/3 validated AEAD backend |
| `password` | `argon2` | Argon2id password hashing and verification |
| `azure-kv` | — | Azure Key Vault key provider (wrap/unwrap only) |
| `mobile-storage` | — | Mobile secure storage: `SensitiveBuffer`, `BackupExclusion`, `MobileStoragePolicy` (MASVS-STORAGE-1) |
| `pq` | `ml-kem`, `x25519-dalek`, `hkdf`, `sha2` | Hybrid post-quantum X25519 + ML-KEM-768 / HKDF-SHA-256 KEM for v2 envelope key wrap. New hybrid envelopes carry `combiner_id = 0x01`; classical v1 envelopes remain unchanged. See [`docs/dev-guide/secure-data-pq.md`](docs/dev-guide/secure-data-pq.md) and [`docs/slo/design/pq-migration-plan.md`](docs/slo/design/pq-migration-plan.md). |

All features are off by default. Enable with `cargo build -p secure_data --features vault,aws-kms`.

### `secure_identity` Feature Flags

| Feature | Dependency | Purpose |
|---|---|---|
| `oidc` | `openidconnect`, `reqwest` | OIDC discovery and PKCE-first authentication |
| `session-redis` | `redis` | Redis-backed session management |
| `biometric` | — | Biometric auth validation, device binding, step-up auth policy (MASVS-AUTH-2, MASVS-AUTH-3) |

All features are off by default. Enable with `cargo build -p secure_identity --features biometric`.

---

## Design Principles

1. **Threat model before code** — No control is built without a documented threat entry.
2. **Default deny everywhere** — Unknown fields rejected, authorization denies by default, secrets hidden from `Debug`/`Display`.
3. **Identity-agnostic authorization** — `secure_authz` depends only on `security_core::IdentitySource`. Bring your own identity provider (Keycloak, Auth0, custom OIDC, or `secure_identity`).
4. **DTO-only writes** — Never deserialize directly into domain models (prevents mass-assignment, OWASP C5).
5. **Envelope encryption** — Application code calls `encrypt_for_storage()` / `decrypt_for_use()`. Key lifecycle, rotation, and AEAD managed by `secure_data`.
6. **Schema-based redaction** — Every telemetry field classified by `DataClassification`. Only `Public` fields leave the process unredacted.

---

## Architecture

See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the full component diagram, crate dependency graph, trust boundary diagram, and security header list.

---

## Developer Documentation

Comprehensive guides for integrating each crate into your Rust applications:

| Guide | Description |
|---|---|
| [`security_core`](./docs/dev-guide/security-core.md) | Shared types, ID newtypes, `CorrelationContext`, `IdentitySource` trait, `DataClassification` |
| [`secure_errors`](./docs/dev-guide/secure-errors.md) | Three-layer error model, `ErrorMappingLayer` middleware, panic boundary, incident IDs |
| [`security_events`](./docs/dev-guide/security-events.md) | Security telemetry, `SecurityEvent` schema, HMAC signing, event correlation, file/batching sinks, redaction, detection engine |
| [`secure_boundary`](./docs/dev-guide/secure-boundary.md) | Input validation extractors, safe types, security headers, CORS, Fetch Metadata, request limits |
| [`secure_output`](./docs/dev-guide/secure-output.md) | Context-aware output encoding (HTML, JSON, URL, JS, CSS, XML, LDAP, shell), URI scheme sanitization |
| [`secure_identity`](./docs/dev-guide/secure-identity.md) | JWT validation (HS256/RS256/ES256), JWKS, OIDC discovery (feature-gated), TOTP MFA, API keys, in-memory + Redis sessions, auth audit events, pluggable identity, biometric auth validation, step-up auth (MASVS-AUTH) |
| [`secure_device_trust`](./docs/dev-guide/secure-device-trust.md) | Native-client bootstrap identity, client type/platform, backend attestation mode, trust-tier decisions |
| [`secure_authz`](./docs/dev-guide/secure-authz.md) | Deny-by-default authorization, RBAC + ABAC + temporal permissions, tenant isolation, bulk checks, `AuthzLayer` middleware |
| [`secure_data`](./docs/dev-guide/secure-data.md) | Secret types, envelope encryption, key rotation, KMS providers (Vault, AWS), FIPS readiness |
| [Integration Guide](./docs/dev-guide/integration-guide.md) | End-to-end middleware ordering, `AppState` setup, request handler patterns, production checklist |

Runbook and project-delivery artifacts live in [`docs/slo/`](docs/slo/README.md):
completed runbooks in [`docs/slo/completed/`](docs/slo/completed/), milestone
summaries in [`docs/slo/completion/`](docs/slo/completion/), and lessons in
[`docs/slo/lessons/`](docs/slo/lessons/).

---

## Threat Model and Attack Trees

- [`THREAT_MODEL.md`](./THREAT_MODEL.md) — Full STRIDE analysis, abuse cases, traceability matrix, residual risks
- [`docs/attack-trees/identity.md`](./docs/attack-trees/identity.md) — Identity/authentication attack paths
- [`docs/attack-trees/authorization.md`](./docs/attack-trees/authorization.md) — Privilege escalation and tenant escape
- [`docs/attack-trees/data-protection.md`](./docs/attack-trees/data-protection.md) — Secret exfiltration and crypto failures
- [`docs/attack-trees/input-output.md`](./docs/attack-trees/input-output.md) — Injection via input and output paths

---

## Build Commands

> All crates build and pass tests. See the [Developer Documentation](#developer-documentation) for integration guides.

```sh
# Build
cargo build --workspace

# Test
cargo test --workspace

# Lint
cargo clippy --workspace --all-targets -- -D warnings

# Documentation
cargo doc --workspace --no-deps

# Supply-chain
cargo audit && cargo deny check && cargo vet

# E2E tests
cargo test --workspace --test 'e2e_*'

# Property tests
cargo test --workspace -- prop_

# CVE regression tests
cargo test --workspace -- cve_

# Timing tests (run locally on a stable machine, not in CI)
cargo test --workspace -- timing_ --ignored

# Fuzz targets (requires nightly + cargo-fuzz)
cargo install cargo-fuzz
cd crates/secure_boundary && cargo +nightly fuzz run fuzz_normalize -- -max_total_time=60
cd crates/secure_boundary && cargo +nightly fuzz run fuzz_deep_link -- -max_total_time=60
cd crates/secure_boundary && cargo +nightly fuzz run fuzz_webview_url -- -max_total_time=60
cd crates/secure_output   && cargo +nightly fuzz run fuzz_html_encode -- -max_total_time=60
cd crates/secure_identity && cargo +nightly fuzz run fuzz_token_validate -- -max_total_time=60
cd crates/secure_data     && cargo +nightly fuzz run fuzz_encrypt_decrypt -- -max_total_time=60
cd crates/secure_data     && cargo +nightly fuzz run fuzz_sensitive_buffer -- -max_total_time=60
cd crates/secure_network  && cargo +nightly fuzz run fuzz_tls_policy -- -max_total_time=60
cd crates/secure_network  && cargo +nightly fuzz run fuzz_cert_pin -- -max_total_time=60
cd crates/secure_network  && cargo +nightly fuzz run fuzz_cleartext -- -max_total_time=60
cd crates/secure_resilience && cargo +nightly fuzz run fuzz_rasp_signals -- -max_total_time=60
cd crates/secure_privacy  && cargo +nightly fuzz run fuzz_pii_classifier -- -max_total_time=60
cd crates/secure_privacy  && cargo +nightly fuzz run fuzz_pseudonymizer -- -max_total_time=60
cd crates/security_events && cargo +nightly fuzz run fuzz_sanitize -- -max_total_time=60
cd crates/security_events && cargo +nightly fuzz run fuzz_mobile_redaction -- -max_total_time=60

# Memory safety (requires nightly)
cargo +nightly miri test --workspace
```

---

## Supply-Chain Security

[![CI](https://github.com/kerberosmansour/SunLitSecurityLibraries/actions/workflows/ci.yml/badge.svg)](https://github.com/kerberosmansour/SunLitSecurityLibraries/actions/workflows/ci.yml)

Every dependency in this workspace is audited, license-checked, and source-verified on every pull request.

### Tools

| Tool | Purpose | Policy |
|---|---|---|
| [`cargo-audit`](https://github.com/rustsec/rustsec/tree/main/cargo-audit) | Known CVE / advisory scanning | All vulnerabilities → error |
| [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) | License compliance, banned crates, source verification | Copyleft denied; only crates.io; no unknown registries |
| [`cargo-vet`](https://mozilla.github.io/cargo-vet/) | Third-party audit trail | All 3rd-party deps exempted or imported from trusted auditors |

### Running Locally

```bash
# Install tools (one-time)
cargo install cargo-audit cargo-deny cargo-vet

# Run all checks (Linux/macOS)
bash scripts/audit.sh

# Run all checks (Windows/PowerShell)
pwsh scripts/audit.ps1

# Run checks individually
cargo audit                  # vulnerability scan
cargo deny check             # license + source policy
cargo vet                    # audit trail
```

### Policy Summary

- **Licenses allowed**: MIT, Apache-2.0, BSD-2/3-Clause, ISC, Zlib, Unicode-3.0, CC0-1.0
- **Copyleft denied** by default; narrow exceptions for unavoidable transitive deps (LGPL: r-efi for UEFI targets; MPL-2.0: smartstring via rhai)
- **Unknown registries denied**: all deps must come from crates.io
- **Unknown git sources denied**: no git dependencies allowed
- **Advisory ignore list**: every entry requires a written justification (see `deny.toml`)
- **Memory-safety attestation**: every workspace crate declares `#![forbid(unsafe_code)]` at lib-root. The posture is regression-tested by [`crates/security_core/tests/no_unsafe_code.rs`](./crates/security_core/tests/no_unsafe_code.rs) — removal fails the build with a named-crate error. The accompanying scan also asserts no `unsafe` keyword appears anywhere in `crates/*/src/`.
- **Transitive `unsafe` visibility**: every PR runs `cargo geiger --workspace --all-features` (advisory, 10-min cap) and uploads the JSON artifact. The number is the upper bound across all features; deltas are visible to reviewers via the artifact diff. See [`docs/dev-guide/unsafe-budget.md`](./docs/dev-guide/unsafe-budget.md) for the posture and threshold-promotion plan.
- **Formal verification** (advisory, in flight): every PR runs `cargo kani` (15-min cap) against the workspace's proof harnesses. M1 ships a bootstrap proof in `secure_data` (nonce non-zero); M2–M5 extend to `secure_authz`, `secure_boundary`, `secure_errors`, plus TLA+ specs for a new `secure_resilience::circuit_breaker` module and the existing `secure_identity` session+step-up flow. See [`docs/dev-guide/formal-verification.md`](./docs/dev-guide/formal-verification.md).

---


```rust
use secure_errors::{
    http::into_response_parts,
    kind::AppError,
    classify::ErrorClassification,
    panic::catch_panic_to_safe_response,
};

// Map an internal error to a safe HTTP response (status + public body).
// Internal details (SQL text, hostnames, policy names) never appear in the response.
let err = AppError::Dependency { dep: "postgres" };
let (status, public_err) = into_response_parts(&err);
// status == 503, public_err.code == "temporarily_unavailable"

// Classify an error for operational decisions.
let cls = ErrorClassification::for_error(&err);
assert!(cls.is_retryable());

// Catch a panic at the service boundary — returns (500, json_body).
let (status, body) = catch_panic_to_safe_response(|| {
    panic!("unexpected state");
});
// status == 500, body contains "internal_error", no panic message
```

---

## `secure_boundary` — Usage Example

Replace axum's plain `Json<T>` with `SecureJson<T>` to enforce the four-stage validation pipeline:

```rust
use axum::{routing::post, Router};
use secure_boundary::{
    extract::SecureJson,
    headers::SecurityHeadersLayer,
    validate::{SecureValidate, ValidationContext},
};
use serde::Deserialize;

// 1. Define a DTO (not a domain model — no sensitive fields like `is_admin`).
#[derive(Deserialize)]
pub struct CreateUserDto {
    pub username: String,
    pub age: u32,
}

// 2. Implement SecureValidate — syntax check is automatic; add semantic rules here.
impl SecureValidate for CreateUserDto {
    fn validate_syntax(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        Ok(()) // Structural type check handled by StrictDeserialize
    }

    fn validate_semantics(&self, _ctx: &ValidationContext) -> Result<(), &'static str> {
        if self.age > 120 {
            return Err("invalid_range");
        }
        Ok(())
    }
}

// 3. Use SecureJson<T> instead of Json<T> in handlers.
async fn create_user(dto: SecureJson<CreateUserDto>) -> &'static str {
    let _inner = dto.into_inner();
    // Unknown fields are rejected automatically.
    // Body size, nesting depth (default 10), and field count (default 100) are enforced.
    "created"
}

// 4. Wrap the router with SecurityHeadersLayer for defense-in-depth headers.
let app = Router::new()
    .route("/users", post(create_user))
    .layer(SecurityHeadersLayer::default());
```

### Safe types — Usage Example

Use safe types in DTOs or standalone to prevent injection attacks:

```rust
use secure_boundary::safe_types::{
    SafePath, SafeUrl, SafeCommandArg, SqlIdentifier,
    SafeFilename, SafeRedirectUrl, LdapSafeString,
};

// SafePath — rejects directory traversal
let path = SafePath::try_from("uploads/image.png")?;          // Ok
let bad  = SafePath::try_from("../../etc/passwd");             // Err (path_traversal)

// SafeUrl — rejects SSRF targets (private IPs, dangerous schemes)
let url  = SafeUrl::try_from("https://api.example.com")?;     // Ok
let bad  = SafeUrl::try_from("http://169.254.169.254/");       // Err (ssrf_attempt)

// SqlIdentifier — alphanumeric + underscore, max 128 chars
let col  = SqlIdentifier::try_from("user_name")?;             // Ok
let bad  = SqlIdentifier::try_from("users; DROP TABLE--");    // Err (injection_attempt)

// SafeCommandArg — rejects shell metacharacters
let arg  = SafeCommandArg::try_from("backup-2024")?;          // Ok
let bad  = SafeCommandArg::try_from("file; rm -rf /");        // Err (command_injection)

// SafeFilename — rejects path separators and shell metacharacters
let name = SafeFilename::try_from("report.pdf")?;             // Ok

// SafeRedirectUrl — relative paths only (open redirect prevention)
let redir = SafeRedirectUrl::try_from("/dashboard")?;         // Ok
let bad   = SafeRedirectUrl::try_from("https://evil.com");    // Err

// LdapSafeString — escapes RFC 4515 special chars; always Ok, emits event if escaping needed
let safe = LdapSafeString::try_from("user*admin")?;
assert!(safe.as_inner().contains("\\2a"));                    // * → \2a

// Use safe types as serde fields in SecureJson DTOs:
#[derive(Deserialize)]
pub struct UploadDto {
    pub file: SafeFilename,
    pub redirect: SafeRedirectUrl,
}
```

### SecureXml — Usage Example

```rust
use secure_boundary::xml::SecureXml;

async fn handle_xml(body: SecureXml<MyXmlDto>) -> String {
    // DOCTYPE / entity declarations blocked; body size limit enforced
    body.into_inner().title
}
```

### CRLF header sanitisation

```rust
use secure_boundary::header_sanitize::sanitize_header_value;

let safe = sanitize_header_value("application/json")?;       // Ok
let bad  = sanitize_header_value("value\r\nX-Evil: yes");    // Err (invalid_header_value)
```

### HTML sanitization (feature: `html-sanitize`)

```rust
use secure_boundary::sanitize::{sanitize_html, SanitizeConfig};

// Strips scripts, event handlers, javascript: URIs — keeps safe HTML
let safe = sanitize_html("<p>Hello</p><script>alert(1)</script>");
// safe == "<p>Hello</p>"

// Custom allow-list
let config = SanitizeConfig::new().allowed_tags(&["b", "i"]);
let safe = config.sanitize("<p><b>bold</b></p>");
// safe contains "<b>bold</b>" but not "<p>"
```

### Per-route limit configuration

```rust
use axum::{routing::post, Extension, Router};
use secure_boundary::limits::RequestLimits;

let strict = RequestLimits::new()
    .with_max_nesting_depth(3)
    .with_max_field_count(20);

let app = Router::new()
    .route("/strict", post(handler))
    .layer(Extension(strict));
```

### Browser security features (CORS, Fetch Metadata, CSP nonce)

```rust
use axum::{http::Method, routing::get, Router};
use secure_boundary::{
    cors::{secure_cors_defaults, SecureCorsBuilder},
    fetch_metadata::FetchMetadataLayer,
    headers::SecurityHeadersLayer,
};

// Deny all cross-origin access by default.
let internal_api = Router::new()
    .route("/internal", get(handler))
    .layer(secure_cors_defaults())
    .layer(FetchMetadataLayer::new());

// Opt in to a specific trusted frontend when cross-origin access is required.
let browser_api = Router::new()
    .route("/public", get(handler))
    .layer(
        SecureCorsBuilder::new()
            .allow_origin("https://app.example.com")
            .allow_methods([Method::GET, Method::POST])
            .build()?
    );

// Add per-request CSP nonces for HTML responses.
let pages = Router::new()
    .route("/", get(handler))
    .layer(SecurityHeadersLayer::new().with_csp_nonce());
# Ok::<(), secure_boundary::CorsConfigError>(())
```

## `secure_output` — Usage Example

```rust
use secure_output::{
    HtmlEncoder, UrlEncoder, JsStringEncoder, CssEncoder, XmlEncoder, OutputEncoder,
    sanitize_uri_scheme,
};

// Encode user input before rendering in HTML context.
let html_enc = HtmlEncoder;
let safe_html = html_enc.encode("<script>alert('xss')</script>");
// safe_html == "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"

// Percent-encode a search term for a URL query parameter.
let url_enc = UrlEncoder;
let encoded_url = url_enc.encode("hello world&q=1");
// encoded_url == "hello%20world%26q%3D1"

// Encode user data for safe embedding in a JavaScript string literal.
let js_enc = JsStringEncoder;
let safe_js = js_enc.encode("user's \"name\"\nwith newline");
// safe_js == r#"user\'s \"name\"\nwith newline"#

// Encode user data for safe embedding in a CSS value.
let css_enc = CssEncoder;
let safe_css = css_enc.encode("expression(alert(1))");
// safe_css == "\\000065xpression\\000028alert\\000028\\000031\\000029\\000029"

// Encode user data for safe embedding in XML content or attributes.
let xml_enc = XmlEncoder;
let safe_xml = xml_enc.encode("<tag attr=\"val\">");
// safe_xml == "&lt;tag attr=&quot;val&quot;&gt;"

// Encode user data for safe embedding in LDAP Distinguished Name components.
use secure_output::ldap::{encode_dn, encode_filter};
let safe_dn = encode_dn("John+Smith,OU=Users");
// safe_dn == "John\+Smith\,OU\=Users"

// Encode user data for safe embedding in LDAP search filters.
let safe_filter = encode_filter("admin)(|(uid=*)");
// Parentheses, asterisks, and backslashes hex-escaped per RFC 4515

// Encode user data for safe use as a POSIX shell argument.
use secure_output::shell;
let safe_arg = shell::encode("file; rm -rf /");
// safe_arg == "'file; rm -rf /'" — single-quoted, semicolon neutralized

// Validate a URI scheme before using it in a redirect or href.
sanitize_uri_scheme("https://example.com").expect("safe");
sanitize_uri_scheme("javascript:alert(1)").expect_err("blocked"); // returns Err
```

---



## `secure_authz` — Usage Example

```rust
use secure_authz::{
    abac::AttributeGuard,
    action::Action,
    decision::Decision,
    enforcer::{Authorizer, DefaultAuthorizer},
    middleware::AuthzLayer,
    policy::DefaultPolicyEngine,
    resource::ResourceRef,
    resolver::{DefaultSubjectResolver, SubjectResolver},
    temporal::PermissionWindow,
};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

// 1. Build a policy engine and add RBAC rules.
let engine = DefaultPolicyEngine::new_empty().await.unwrap();
engine.add_policy("editor", "article", "write").await.unwrap();
let engine = Arc::new(engine);

// 2. Create the authorizer (optional ABAC + temporal constraints).
let now = OffsetDateTime::now_utc();
let authorizer = DefaultAuthorizer::new(engine)
    .with_abac_guard(AttributeGuard::require_subject_attr("department", "engineering"))
    .with_time_source(move || now);

// 3. Resolve an identity to a Subject using DefaultSubjectResolver.
//    The identity can come from ANY IdentitySource (secure_identity, Keycloak, etc.).
let mut subject = DefaultSubjectResolver::resolve(&authenticated_identity);
PermissionWindow::new()
    .starting_at(now - Duration::minutes(5))
    .expiring_at(now + Duration::hours(8))
    .apply_to_subject(&mut subject)
    .unwrap();

// 4. Check authorization — deny by default.
let resource = ResourceRef::new("article").with_tenant("acme");
let decision = authorizer.authorize(&subject, &Action::Write, &resource).await;
match decision {
    Decision::Allow { .. } => { /* proceed */ }
    Decision::Deny { reason } => { /* return 403, log reason */ }
}

// 5. Protect axum routes with AuthzLayer middleware.
let router = axum::Router::new()
    .route("/articles", axum::routing::post(create_article))
    .layer(AuthzLayer::new(
        Arc::new(authorizer),
        Action::Create,
        ResourceRef::new("article"),
    ));
```

---

## `secure_data` — Usage Example

```rust
use secure_data::{
    config::SecretReference,
    envelope::{decrypt_for_use, encrypt_for_storage},
    kms::StaticDevKeyProvider,
    secret::SecretString,
};

// 1. Secrets are typed wrappers — never raw String.
//    Debug output and JSON serialization are automatically redacted.
let db_password = SecretString::new("my-db-pass".to_string());
println!("{:?}", db_password); // → SecretString([REDACTED])
let json = serde_json::to_string(&db_password).unwrap(); // → "[REDACTED]"

// 2. Envelope encryption — application code never touches AEAD directly.
let provider = StaticDevKeyProvider::new(); // use VaultKeyProvider or AwsKmsKeyProvider in production
let plaintext = b"sensitive data to protect";

let envelope = encrypt_for_storage(plaintext, "app-data-key", &provider)
    .await
    .expect("encryption must succeed");
// envelope.ciphertext is AES-256-GCM ciphertext; nonce is random per call

let recovered = decrypt_for_use(&envelope, &provider)
    .await
    .expect("decryption must succeed");
assert_eq!(recovered, plaintext);

// 3. Crypto agility — switch algorithms without changing application code.
use secure_data::algorithm::{AlgorithmPolicy, CryptoAlgorithm};
use secure_data::envelope::encrypt_with_policy;
let policy = AlgorithmPolicy::prefer(CryptoAlgorithm::XChaCha20Poly1305);
let envelope = encrypt_with_policy(plaintext, "app-key", &provider, &policy)
    .await
    .expect("encryption must succeed");
assert_eq!(envelope.algorithm, "XChaCha20-Poly1305");
// Old AES-256-GCM envelopes still decrypt transparently.

// 4. Password hashing — Argon2id with secure defaults (feature "password").
#[cfg(feature = "password")]
{
    use secure_data::password::{hash_password, verify_password};
    let pw = SecretString::new("correct-horse-battery".to_string());
    let hash = hash_password(&pw).expect("hash must succeed");
    assert!(hash.expose_hash().starts_with("$argon2id$"));
    assert!(verify_password(&pw, &hash).expect("verify must succeed"));
}

// 4. Secret references in config — not raw secrets.
let db_ref = SecretReference::parse("vault://kv/prod-db#password")
    .expect("valid reference");
// db_ref.provider == SecretReferenceProvider::Vault
// db_ref.path == "kv/prod-db"
// db_ref.field == Some("password")
```

---

## Running the Reference Service

The `secure_reference_service` binary composes all eight library crates into a working axum application demonstrating canonical middleware ordering and full security coverage.

```bash
# Run the reference service (binds to 127.0.0.1:3000)
cargo run -p secure_reference_service

# In another terminal — create an item (requires X-Dev-Subject header):
curl -s -X POST http://localhost:3000/items \
  -H 'Content-Type: application/json' \
  -H 'X-Dev-Subject: 00000000-0000-0000-0000-000000000001' \
  -H 'X-Dev-Roles: admin' \
  -d '{"name":"hello"}'

# Request without authentication → 401:
curl -s -o /dev/null -w "%{http_code}" \
  -X POST http://localhost:3000/items \
  -H 'Content-Type: application/json' \
  -d '{"name":"hello"}'
# → 401

# Unknown JSON field → 422 (rejected at boundary):
curl -s -o /dev/null -w "%{http_code}" \
  -X POST http://localhost:3000/items \
  -H 'Content-Type: application/json' \
  -H 'X-Dev-Subject: 00000000-0000-0000-0000-000000000001' \
  -H 'X-Dev-Roles: admin' \
  -d '{"name":"x","admin":true}'
# → 422
```

> **WARNING**: `X-Dev-Subject` / `X-Dev-Roles` headers are for **development only**.
> Replace `DevAuthLayer` with a real `IdentitySource` implementation before any production deployment.

---

## Running the Smoke-Test Service

The `secure_smoke_service` binary exposes 54 routes, each targeting a specific attack class. It uses `TokenValidator` (HS256 JWT) instead of `DevAuthLayer`. This includes 15 mobile routes under `/smoke/mobile/` covering MASVS-NETWORK, MASVS-STORAGE, MASVS-AUTH, MASVS-PLATFORM, MASVS-RESILIENCE, and MASVS-PRIVACY controls.

```bash
# Run the smoke-test service (binds to 127.0.0.1:3001)
cargo run -p secure_smoke_service

# Health check:
curl -s http://localhost:3001/health
# → ok

# XSS — HTML-encoded reflection:
curl -s -X POST http://localhost:3001/smoke/xss \
  -H 'Content-Type: application/json' \
  -d '{"content":"<script>alert(1)</script>"}'
# → {"safe_html":"&lt;script&gt;alert(1)&lt;/script&gt;"}

# SQL injection — rejected:
curl -s -o /dev/null -w "%{http_code}" \
  -X POST http://localhost:3001/smoke/sqli \
  -H 'Content-Type: application/json' \
  -d "{\"search\":\"'; DROP TABLE users; --\"}"
# → 422

# Security headers:
curl -s -D- http://localhost:3001/smoke/headers | head -20
```

### Route Table

| Category | Routes | Count |
|---|---|---|
| Input validation | xss, sqli, cmdi, path-traversal, xxe, deserialization, mass-assignment, header-injection, unicode-bypass, body-bomb, deep-nesting, field-flood | 12 |
| Output encoding | reflect-html, reflect-url, reflect-json, headers | 4 |
| Authentication | jwt, expired, alg-none, tampered, wrong-issuer, session | 6 |
| Authorization | allow, deny, cross-tenant, privilege-escalation, idor | 5 |
| Data protection | encrypt, decrypt, decrypt-tampered, secret-debug, key-rotation | 5 |
| Error handling | internal, dependency, panic, validation | 4 |
| Security events | log-injection, redaction | 2 |
| Health | /health | 1 |

OpenAPI 3.1 spec for OWASP ZAP: `crates/secure_smoke_service/openapi.yaml`.

---

## OWASP ZAP DAST Scanning

The workspace keeps local DAST (Dynamic Application Security Testing) tooling
for [OWASP ZAP](https://www.zaproxy.org/) (Checkmarx ZAP). ZAP scans the smoke
service's OpenAPI spec and can gate on high/critical findings when run locally.
CI uses Dastardly as the single PR DAST lane to avoid duplicate long-running
GitHub Actions scans.

### Prerequisites

- Docker installed and running
- python3 available
- Rust toolchain (cargo)

### Running a ZAP Scan Locally

```bash
# Full scan: build, start service, run ZAP, check results
bash scripts/zap_scan.sh

# Skip build if binary already exists
bash scripts/zap_scan.sh --no-build

# Keep the smoke service running after the scan
bash scripts/zap_scan.sh --keep-service
```

### Outputs

| File | Description |
|---|---|
| `output/zap-report.html` | Human-readable ZAP report |
| `output/zap-report.json` | Machine-readable report for CI gating |

### CI Integration

ZAP does not run automatically in GitHub Actions. Use the local script when a
change needs OpenAPI-driven ZAP coverage. Pull requests use the Dastardly
workflow below as the CI DAST gate.

### Customisation

- **Rule tuning**: Edit `scripts/zap-rules.tsv` to change alert actions (IGNORE/WARN/FAIL)
- **Baseline suppressions**: Add known false positives to `scripts/zap-baseline.json` with mandatory written justification
- **Report parsing**: `scripts/zap_check.py` exits non-zero on any High (risk code ≥ 3) finding not suppressed by the baseline

---

## Dastardly (Burp Suite) DAST Scanning

[Dastardly](https://portswigger.net/burp/dastardly) is a free, lightweight DAST
scanner from PortSwigger, powered by the same engine as Burp Suite. It is the
CI DAST gate for pull requests and checks for XSS (reflected & stored), SQL
injection, OS command injection, path traversal, SSRF, XXE, and improper input
handling.

### Running a Dastardly Scan Locally

```bash
# Full scan: build, start service, run Dastardly, check results
bash scripts/dastardly_scan.sh

# Skip build if binary already exists
bash scripts/dastardly_scan.sh --no-build

# Keep the smoke service running after the scan
bash scripts/dastardly_scan.sh --keep-service
```

### Outputs

| File | Description |
|---|---|
| `output/dastardly-report.xml` | JUnit XML report with vulnerability details |

### CI Integration

The Dastardly scan runs automatically in CI via `.github/workflows/dastardly.yml` on every push and PR to `main`. The workflow:

1. Builds and starts `secure_smoke_service`
2. Runs Dastardly via the official `PortSwigger/dastardly-github-action`
3. Publishes results as a JUnit test report
4. Uploads the XML report as a build artifact

---

## Milestones

This table summarizes the original foundation milestones. Later hardening,
MASVS, OWASP alignment, and public-release work is captured under
[`docs/slo/`](docs/slo/README.md).

| # | Milestone | Status |
|---|---|---|
| 0 | Threat model & security requirements | ✅ done |
| 1 | Workspace scaffold + `security_core` | ✅ done |
| 2 | `secure_errors` | ✅ done |
| 3 | `security_events` | ✅ done |
| 4 | `secure_boundary` + `secure_output` | ✅ done |
| 5 | `secure_identity` | ✅ done |
| 6 | `secure_authz` | ✅ done |
| 7 | `secure_data` | ✅ done |
| 8 | Reference service + axum integration | ✅ done |
| 9 | Adversarial testing | ✅ done |
| 10 | Supply-chain hardening + CI | ✅ done |

---

## License

This project is dual-licensed under either of:

- [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](https://opensource.org/licenses/MIT)

at your option. Every `crates/*/Cargo.toml` declares
`license = "MIT OR Apache-2.0"`, matching [LICENSE](LICENSE) and [NOTICE](NOTICE).

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this repository is dual-licensed the same way. See
[CONTRIBUTING.md](CONTRIBUTING.md#sign-off-and-licensing).

---

## Contributing

Contributions are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md), use
the PR template, and link the relevant issue or runbook when there is one. For
security-sensitive changes, update [THREAT_MODEL.md](THREAT_MODEL.md) or the
relevant dev guide when the trust boundary or security invariant changes.

Project governance is documented in [GOVERNANCE.md](GOVERNANCE.md), current
maintainers in [MAINTAINERS.md](MAINTAINERS.md), and user-facing changes in
[CHANGELOG.md](CHANGELOG.md). This project uses the
[Contributor Covenant 2.1](CODE_OF_CONDUCT.md).

## Security

Please do not open public issues for vulnerabilities. Report them through
GitHub private advisories:

https://github.com/kerberosmansour/SunLitSecurityLibraries/security/advisories/new

Supported versions, response targets, and scope are documented in
[SECURITY.md](SECURITY.md).

## Trademarks

The project names and associated logos are reserved trademarks of Sherif
Mansour. The code license grants rights in the code, not the names or logos.
See [TRADEMARKS.md](TRADEMARKS.md).

---

## Dev guide index

Engineer-facing documentation for consuming these libraries lives in [`docs/dev-guide/`](docs/dev-guide/README.md):

- [Framework adapter — `secure_boundary` on Actix-web 4](docs/dev-guide/secure_boundary-actix.md)
- [Framework adapter — `secure_authz` on Actix-web 4](docs/dev-guide/secure_authz-actix.md)
- [Framework adapter — `secure_errors` on Actix-web 4](docs/dev-guide/secure_errors-actix.md)
- [SSRF prevention with `SafeUrl`](docs/dev-guide/safe-url-ssrf.md)
- [Production deployment checklist](docs/dev-guide/production-checklist.md)

---

## Supply-chain policy

The canonical supply-chain policy lives at [`deny.toml`](./deny.toml) at the repo root. Downstream consumers may copy or `curl` it directly to adopt the same policy (licenses allowed, banned crates, source verification). The policy is enforced on every PR via the `supply-chain` job in `.github/workflows/ci.yml` (`cargo audit` + `cargo deny check` + `cargo vet`).
