# SunLit Security Libraries — Improvement Proposal

> **Date**: April 2026
> **Scope**: Post-M10 enhancement roadmap
> **Based on**: Full codebase audit, lessons learned (M0–M10), threat model, architecture review

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Security Test Microservice (`secure_smoke_service`)](#2-security-test-microservice-secure_smoke_service)
3. [Input Validation Gaps](#3-input-validation-gaps)
4. [Output Encoding Gaps](#4-output-encoding-gaps)
5. [Data Protection — Real Provider Integrations](#5-data-protection--real-provider-integrations)
6. [Identity & Authentication Gaps](#6-identity--authentication-gaps)
7. [Authorization Enhancements](#7-authorization-enhancements)
8. [Security Events & Observability](#8-security-events--observability)
9. [Error Handling Improvements](#9-error-handling-improvements)
10. [OWASP ZAP (Checkmarx ZAP) Integration](#10-owasp-zap-checkmarx-zap-integration)
11. [Supply-Chain & CI Improvements](#11-supply-chain--ci-improvements)
12. [Prioritized Build Plan](#12-prioritized-build-plan)

---

## 1. Executive Summary

The SunLit Security Libraries workspace has completed M0–M10: threat model, eight security crates, a reference service, adversarial testing, and supply-chain hardening. All OWASP Proactive Controls (C1/C4–C10) have foundational implementations.

This proposal identifies **concrete gaps** uncovered by auditing every source file, test file, lesson-learned document, and the architecture against real-world attack scenarios. The gaps fall into three categories:

| Category | Count | Severity |
|---|---|---|
| Missing attack-class coverage (input/output) | 12 | Critical–High |
| Missing production integrations (KMS, Vault, OIDC) | 8 | Critical |
| Missing validation tooling (ZAP, smoke tests) | 5 | High |
| Enhancement opportunities (authz, events, errors) | 14 | Medium |

The single highest-impact deliverable is a **security smoke-test microservice** that exercises every crate's security controls against real attack payloads, paired with automated **OWASP ZAP scanning** to validate the controls hold under adversarial HTTP traffic.

---

## 2. Security Test Microservice (`secure_smoke_service`)

### 2.1 Problem

The existing `secure_reference_service` demonstrates integration but is a **CRUD demo** with in-memory storage and `DevAuthLayer`. It does not:

- Exercise every attack class that the crates are designed to prevent
- Provide endpoints that intentionally expose vulnerable patterns for validation
- Include a comprehensive smoke-test suite proving each control stops each attack
- Support automated DAST scanning (OWASP ZAP)

### 2.2 Proposal: New Crate `secure_smoke_service`

Create a new crate `crates/secure_smoke_service/` — a purpose-built axum microservice that:

1. **Exposes routes covering every security control** — each endpoint maps to a specific OWASP category
2. **Includes attack payload test suites** in the integration tests
3. **Serves as the ZAP scan target** with OpenAPI spec for guided scanning
4. **Uses real (or near-real) integrations** — JWT auth, persistent sessions, Vault/KMS stubs with interface contracts

### 2.3 Required Routes & Coverage

#### Input Validation Routes (`secure_boundary`)

| Route | Method | Attack Class Tested | Expected Behaviour |
|---|---|---|---|
| `/smoke/xss` | POST | Reflected XSS via JSON field | Input accepted, output HTML-encoded via `secure_output` |
| `/smoke/sqli` | POST | SQL injection via search param | Rejected or parameterised (safe types) |
| `/smoke/cmdi` | POST | OS command injection via filename | Rejected by command-safe type |
| `/smoke/path-traversal` | GET | `../../etc/passwd` in path param | Rejected by path-safe type |
| `/smoke/xxe` | POST | XML entity expansion in body | Rejected (XML parsing denied or entity-stripped) |
| `/smoke/deserialization` | POST | Malicious JSON (nested bombs, type confusion) | Rejected by nesting/field limits |
| `/smoke/mass-assignment` | POST | Extra `is_admin` field in DTO | Unknown field rejected at boundary |
| `/smoke/header-injection` | POST | CRLF in header value | Rejected or sanitised |
| `/smoke/unicode-bypass` | POST | NFC/NFKC bypass attempts | Normalised before validation |
| `/smoke/body-bomb` | POST | 10 MB JSON body | Rejected by size limit (413) |
| `/smoke/deep-nesting` | POST | 500-level nested JSON | Rejected by depth limit |
| `/smoke/field-flood` | POST | JSON with 10,000 fields | Rejected by field count limit |

#### Output Encoding Routes (`secure_output`)

| Route | Method | Attack Class Tested | Expected Behaviour |
|---|---|---|---|
| `/smoke/reflect-html` | GET | User input reflected in HTML response | HTML-encoded output, no raw `<script>` |
| `/smoke/reflect-url` | GET | User input in redirect URL | URL-encoded, no open redirect |
| `/smoke/reflect-json` | GET | User input in `<script>` JSON block | `</script>` escaped to `<\/script>` |
| `/smoke/headers` | GET | Security header validation | All OWASP headers present |

#### Authentication Routes (`secure_identity`)

| Route | Method | Attack Class Tested | Expected Behaviour |
|---|---|---|---|
| `/smoke/auth/jwt` | POST | Valid JWT → identity resolved | 200 with actor info |
| `/smoke/auth/expired` | POST | Expired JWT | 401 |
| `/smoke/auth/alg-none` | POST | `alg: none` JWT | 401 (CVE-2015-9235) |
| `/smoke/auth/tampered` | POST | Modified JWT signature | 401 |
| `/smoke/auth/wrong-issuer` | POST | JWT from wrong IdP | 401 |
| `/smoke/auth/session` | POST/GET | Session create/validate/revoke | Full lifecycle |

#### Authorization Routes (`secure_authz`)

| Route | Method | Attack Class Tested | Expected Behaviour |
|---|---|---|---|
| `/smoke/authz/allow` | GET | Authorised role + tenant | 200 |
| `/smoke/authz/deny` | GET | Missing role | 403 |
| `/smoke/authz/cross-tenant` | GET | Access resource in different tenant | 403 |
| `/smoke/authz/privilege-escalation` | POST | Low-privilege role attempts admin action | 403 |
| `/smoke/authz/idor` | GET | Access resource owned by another user | 403 |

#### Data Protection Routes (`secure_data`)

| Route | Method | Attack Class Tested | Expected Behaviour |
|---|---|---|---|
| `/smoke/encrypt` | POST | Encrypt plaintext via envelope API | Returns encrypted envelope |
| `/smoke/decrypt` | POST | Decrypt valid envelope | Returns plaintext |
| `/smoke/decrypt-tampered` | POST | Tampered ciphertext | 400 (AEAD failure) |
| `/smoke/secret-debug` | GET | Secret type in response | `[REDACTED]` — no raw secret |
| `/smoke/key-rotation` | POST | Rotate key, re-encrypt | Old data still decryptable |

#### Error Handling Routes (`secure_errors`)

| Route | Method | Attack Class Tested | Expected Behaviour |
|---|---|---|---|
| `/smoke/error/internal` | GET | Trigger internal error | 500, no stack trace in response |
| `/smoke/error/dependency` | GET | Trigger dependency error | 503, no hostname/SQL leak |
| `/smoke/error/panic` | GET | Trigger panic | 500, panic message hidden |
| `/smoke/error/validation` | POST | Invalid input | 400, stable error code only |

#### Security Events Routes (`security_events`)

| Route | Method | Attack Class Tested | Expected Behaviour |
|---|---|---|---|
| `/smoke/events/log-injection` | POST | Newline/CRLF in loggable field | Sanitised in audit output |
| `/smoke/events/redaction` | POST | PII field in event | SHA256-hashed in log output |

### 2.4 Smoke Test Suite

Integration tests in `tests/smoke_tests.rs` should:

1. Start the service on a random port
2. Fire every attack payload from the table above
3. Assert correct HTTP status codes
4. Assert response bodies contain no internal details
5. Assert security headers present on every response
6. Assert security events emitted for attack signals
7. Produce a **test report** summarising pass/fail per attack class

### 2.5 OpenAPI Specification

Generate or hand-write `openapi.yaml` for the smoke service to enable OWASP ZAP's API scan mode. Every route must include:
- Request schema with examples (including malicious payloads)
- Expected response codes
- Security schemes (Bearer JWT)

---

## 3. Input Validation Gaps

### 3.1 Currently Missing Attack-Class Defences

These attack classes are **not covered** by `secure_boundary` today:

| # | Attack Class | Gap | Proposed Solution |
|---|---|---|---|
| 1 | **Directory/Path Traversal** | No detection of `../`, `..\\`, null bytes in path parameters | Add `SafePath` newtype that rejects traversal sequences, resolves to canonical path, validates against an allowed root |
| 2 | **SQL Injection** | No SQL-aware validation or safe types | Add `SqlIdentifier` safe type (alphanumeric + underscore only); document that parameterised queries are the primary defence — the crate provides a type-safety backstop |
| 3 | **OS Command Injection** | No shell metacharacter detection | Add `SafeFilename` and `SafeCommandArg` types that reject `;`, `|`, `&`, `` ` ``, `$()`, `>`, `<`, `\n` |
| 4 | **XML External Entity (XXE)** | No XML handling at all | Add `SecureXml` extractor that parses XML with entity expansion disabled, DTD processing disabled, and external entity resolution blocked. Consider using `quick-xml` with safe defaults |
| 5 | **Deep Nesting / JSON Bomb** | `max_nesting_depth` defined in `RequestLimits` but **never enforced** during extraction | Wire `max_nesting_depth` check into `SecureJson` extractor using a custom serde deserializer or `serde_json::StreamDeserializer` with depth tracking |
| 6 | **Field Count Exhaustion** | `max_field_count` defined in `RequestLimits` but **never enforced** | Wire field-count check into `SecureJson` using a counting deserializer wrapper |
| 7 | **Header Injection (CRLF)** | No CRLF detection in user-supplied values used as headers | Add `sanitize_header_value()` that strips or rejects `\r` and `\n` |
| 8 | **SSRF** | No URL validation for user-supplied URLs | Add `SafeUrl` type that rejects private/internal IP ranges (RFC 1918, link-local, loopback), `file://`, `gopher://`, and non-HTTP(S) schemes |
| 9 | **Open Redirect** | No redirect URL validation | Add `SafeRedirectUrl` that validates against an allowlist of domains or relative paths only |
| 10 | **NoSQL Injection** | No MongoDB operator injection prevention | Add `sanitize_nosql()` that rejects `$`-prefixed keys in JSON objects |
| 11 | **Log Forging (input side)** | Handled in `security_events` at output but not at boundary input | Add detection of control characters in text inputs at the `SecureValidate` level |
| 12 | **LDAP Injection** | No LDAP filter/DN encoding | Add `LdapSafeString` type that escapes LDAP metacharacters per RFC 4515 |

### 3.2 Proposed New Module: `crates/secure_boundary/src/safe_types.rs`

```rust
// Type-safe wrappers that reject dangerous input at construction time
pub struct SafePath { /* rejects ../, ..\, null bytes, non-canonical */ }
pub struct SafeFilename { /* rejects /, \, .., null, shell metacharacters */ }
pub struct SafeCommandArg { /* rejects ;|&`$><\n\r */ }
pub struct SafeUrl { /* rejects private IPs, non-HTTPS, file:/gopher: */ }
pub struct SafeRedirectUrl { /* allowlist-based domain or relative-only */ }
pub struct SqlIdentifier { /* alphanumeric + underscore, max 128 chars */ }
pub struct LdapSafeString { /* RFC 4515 escaped */ }
```

Each type should:
- Implement `TryFrom<&str>` with descriptive error
- Implement `Deserialize` that runs validation during serde parsing
- Work with `SecurePath`, `SecureQuery`, `SecureJson` extractors
- Emit `BoundaryViolation` security event on rejection

### 3.3 Enforce Existing Limits

The `RequestLimits` struct already defines `max_nesting_depth` and `max_field_count` but these are **dead code** — never checked during request processing. This must be wired in.

---

## 4. Output Encoding Gaps

### 4.1 Missing Encoding Contexts

| # | Context | Current Status | Risk | Proposed Solution |
|---|---|---|---|---|
| 1 | **JavaScript string** | Not implemented | XSS in inline `<script>` blocks | Add `JsStringEncoder` — escapes `'`, `"`, `\`, `/`, newlines, Unicode line/paragraph separators per OWASP guidelines |
| 2 | **CSS** | Not implemented | CSS injection (`expression()`, `url()`) | Add `CssEncoder` — escapes CSS metacharacters per OWASP CSS encoding rules |
| 3 | **XML** | Not implemented | XML injection when generating XML responses | Add `XmlEncoder` — encodes `<`, `>`, `&`, `"`, `'` for XML attribute/element contexts |
| 4 | **LDAP** | Not implemented | LDAP injection in DN/filter contexts | Add `LdapEncoder` — escapes per RFC 4514 (DN) and RFC 4515 (filter) |
| 5 | **Shell/Command** | Not implemented | Command injection in shell contexts | Add `ShellEncoder` — escapes shell metacharacters for `sh`/`bash` |
| 6 | **Protocol URI sanitiser** | Not implemented | `javascript:`, `data:`, `vbscript:` in `href`/`src` | Add `sanitize_uri_scheme()` that allowlists `http:`, `https:`, `mailto:` only |

### 4.2 Security Headers Enhancement

The `SecurityHeadersLayer` in `secure_boundary` covers the basics but could be extended:

| Header | Current | Enhancement |
|---|---|---|
| `Content-Security-Policy` | `default-src 'none'` | Add nonce-based CSP support for inline scripts |
| `Cross-Origin-Embedder-Policy` | Missing | Add `require-corp` |
| `Cross-Origin-Opener-Policy` | Missing | Add `same-origin` |
| `Cross-Origin-Resource-Policy` | Missing | Add `same-origin` |
| `X-Permitted-Cross-Domain-Policies` | Missing | Add `none` |
| `X-DNS-Prefetch-Control` | Missing | Add `off` |

---

## 5. Data Protection — Real Provider Integrations

### 5.1 Current State

- `KeyProvider` is a sealed trait with only `StaticDevKeyProvider` (XOR-based, dev-only)
- `SecretReference::parse()` handles `vault://`, `kms://`, `env://` URIs but **never resolves** them
- No integration with any real KMS or secrets manager

### 5.2 Proposed: `VaultKeyProvider`

```
crates/secure_data/src/providers/vault.rs
```

| Feature | Details |
|---|---|
| Backend | HashiCorp Vault (Transit secrets engine) |
| Auth methods | Token, AppRole, Kubernetes |
| Operations | `generate_data_key`, `unwrap_data_key`, key rotation via Vault API |
| Caching | Local DEK cache with TTL to reduce Vault round-trips |
| Lease renewal | Automatic token/secret lease renewal |
| Dependencies | `reqwest` (HTTP client), `serde_json` |
| Feature gate | `vault` Cargo feature — off by default |

### 5.3 Proposed: `AwsKmsKeyProvider`

```
crates/secure_data/src/providers/aws_kms.rs
```

| Feature | Details |
|---|---|
| Backend | AWS KMS |
| Auth methods | IAM Role, environment credentials, IRSA (EKS) |
| Operations | `GenerateDataKey`, `Decrypt` (unwrap) |
| Region support | Configurable AWS region |
| Dependencies | `aws-sdk-kms`, `aws-config` |
| Feature gate | `aws-kms` Cargo feature — off by default |

### 5.4 Proposed: `AzureKeyVaultProvider`

```
crates/secure_data/src/providers/azure_kv.rs
```

| Feature | Details |
|---|---|
| Backend | Azure Key Vault |
| Auth methods | Managed Identity, service principal |
| Operations | Wrap/unwrap key, encrypt/decrypt |
| Dependencies | `azure_security_keyvault` |
| Feature gate | `azure-kv` Cargo feature — off by default |

### 5.5 Proposed: Secret Reference Resolution

Currently `SecretReference::parse()` returns a struct but nothing resolves it. Add:

```rust
pub async fn resolve_secret(reference: &SecretReference) -> Result<SecretString, DataError> {
    match reference.provider {
        Vault => vault_client.read_secret(reference.path, reference.field).await,
        Kms => kms_client.decrypt(reference.path).await,
        Env => std::env::var(reference.path).map(SecretString::new).map_err(..),
    }
}
```

### 5.6 Persistent KeyRing

The `KeyRing` is currently in-memory (`HashMap`). For production:

- Add `KeyRingStore` trait with `load()` / `save()` methods
- Implement `FileKeyRingStore` (encrypted JSON on disk)
- Implement `DatabaseKeyRingStore` (SQL-backed, for multi-instance sync)

---

## 6. Identity & Authentication Gaps

### 6.1 Current State

- JWT validation: HS256 only, static shared secret
- Sessions: in-memory only (`HashMap`)
- MFA: stub trait, no implementation
- No OIDC discovery, no JWKS rotation, no asymmetric algorithms

### 6.2 Proposed Improvements

| # | Feature | Description | Priority |
|---|---|---|---|
| 1 | **Asymmetric JWT (RS256/ES256)** | Support RSA and ECDSA token verification — required for any IdP integration (Keycloak, Auth0, Okta) | Critical |
| 2 | **JWKS endpoint support** | Fetch and cache public keys from `.well-known/jwks.json` with automatic rotation | Critical |
| 3 | **OIDC Discovery** | Auto-configure issuer, JWKS URI, and endpoints from `.well-known/openid-configuration` | High |
| 4 | **Persistent session backend** | `RedisSessionManager` and `DatabaseSessionManager` implementing `SessionManager` trait | High |
| 5 | **API Key authentication** | `ApiKeyAuthenticator` — validate API keys against a store with constant-time comparison | High |
| 6 | **TOTP MFA** | Implement `MfaProvider` with TOTP generation and verification using `totp-rs` | Medium |
| 7 | **Token refresh** | Refresh token flow with rotation (one-time-use refresh tokens) | Medium |
| 8 | **Rate limiting on auth** | Per-IP and per-account rate limiting on authentication endpoints | Medium |
| 9 | **mTLS identity extraction** | Extract client certificate DN/SAN as identity source for service-to-service auth | Medium |
| 10 | **Authentication success auditing** | Emit security events on successful authentication, not just failures | Low |

---

## 7. Authorization Enhancements

### 7.1 Current State

- Deny-by-default RBAC via casbin
- Tenant isolation enforced
- Decision cache with policy-version invalidation
- `AuthzLayer` middleware for axum

### 7.2 Proposed Improvements

| # | Feature | Description | Priority |
|---|---|---|---|
| 1 | **Cache key includes tenant_id** | Current `CacheKey` excludes tenant — two tenants with same actor/resource/action share cache entries (privacy risk) | Critical |
| 2 | **Obligation enforcement** | `Decision::Allow` carries `obligations: Vec<String>` but middleware ignores them — wire enforcement | High |
| 3 | **Policy hot-reload** | Watch policy source (file or API) and reload without restart; maintain version history | High |
| 4 | **Row-level security** | Integrate resource ownership/tenant checks into query-level filtering, not just route-level | Medium |
| 5 | **Hierarchical resources** | Support resource trees (org → project → item) with permission inheritance | Medium |
| 6 | **Bulk authorization** | `authorize_batch(subject, [(action, resource)])` for list endpoints — avoids N+1 authz calls | Medium |
| 7 | **Fine-grained deny reasons** | Distinguish "no matching role" from "role exists but wrong action" in `DenyReason` | Low |
| 8 | **Delegation/impersonation** | Temporary role elevation with audit trail (admin acting as user for support) | Low |

---

## 8. Security Events & Observability

### 8.1 Current State

- Structured events with DataClassification-driven redaction
- Log injection prevention via sanitisation
- AppSensor-style detection points
- Hash-chained audit trail
- Rate limiting per EventKind
- Two sinks: StdoutJson, Tracing (both sealed)

### 8.2 Proposed Improvements

| # | Feature | Description | Priority |
|---|---|---|---|
| 1 | **Unseal `SecuritySink`** or add more sinks | Add `FileSink`, `SyslogSink`, `HttpWebhookSink` for SIEM integration (ELK, Splunk, Datadog) | High |
| 2 | **HMAC-signed audit entries** | Sign each `ChainedAuditEntry` with HMAC — hash chain detects tampering but not forgery | High |
| 3 | **Async batch emission** | Buffer events and flush in batches to reduce I/O overhead under high load | Medium |
| 4 | **Distributed tracing middleware** | Tower middleware that auto-populates `trace_id` / `request_id` into security events | Medium |
| 5 | **Event correlation** | `parent_event_id` field for causal chains (auth failure → brute force detection → account lockout) | Medium |
| 6 | **Audit retention policy** | TTL-based archival/deletion of old audit chain entries | Low |
| 7 | **SBOM event** | Emit startup event with dependency inventory for runtime audit | Low |

---

## 9. Error Handling Improvements

### 9.1 Current State

- Three-layer model: internal → classified → public
- Centralised HTTP mapping
- Panic boundary
- SecurityIncident trait (sealed)

### 9.2 Proposed Improvements

| # | Feature | Description | Priority |
|---|---|---|---|
| 1 | **Auto-mapping middleware** | Tower middleware that catches `AppError` from handlers and calls `into_response_parts()` automatically — no manual mapping in every handler | High |
| 2 | **Context propagation** | Task-local or extension-based automatic attachment of `request_id`, `actor_id`, `tenant_id` to every `ErrorReport` | High |
| 3 | **Retry-after in RateLimit** | `AppError::RateLimit` should carry `retry_after_seconds` for 429 responses with `Retry-After` header | Medium |
| 4 | **Error chaining** | `.context("additional info")` pattern (like `anyhow`) for richer internal diagnostics without leaking | Medium |
| 5 | **Circuit breaker** | Track consecutive `Dependency` errors and short-circuit to 503 before backend hammering | Low |

---

## 10. OWASP ZAP (Checkmarx ZAP) Integration

### 10.1 Overview

[OWASP ZAP](https://www.zaproxy.org/) (now maintained under the Checkmarx umbrella) is the industry-standard DAST (Dynamic Application Security Testing) tool for web applications. It should be integrated into the CI pipeline to validate that the security controls actually hold under automated attack traffic.

### 10.2 Integration Plan

#### Phase 1: Local ZAP Scan Script

Create `scripts/zap_scan.sh`:

```bash
#!/bin/bash
# 1. Build and start the smoke service
cargo build -p secure_smoke_service
cargo run -p secure_smoke_service &
SERVICE_PID=$!
sleep 3

# 2. Run ZAP API scan against OpenAPI spec
docker run --rm --network host \
  -v $(pwd)/crates/secure_smoke_service/openapi.yaml:/zap/openapi.yaml \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-api-scan.py \
    -t http://localhost:3000/openapi.yaml \
    -f openapi \
    -r /zap/report.html \
    -c /zap/zap-config.prop \
    -J /zap/report.json

# 3. Check for high/critical findings
# Parse JSON report for FAIL conditions
python3 scripts/zap_check.py report.json

# 4. Cleanup
kill $SERVICE_PID
```

#### Phase 2: ZAP Configuration

Create `scripts/zap-config.prop` with:

- Active scan rules enabled for: XSS, SQLi, path traversal, command injection, CRLF injection, XXE
- Passive scan rules enabled for: missing security headers, cookie flags, information disclosure
- Authentication configured via Bearer JWT token
- Session management via token handling
- Scan policy tuned to focus on the attack classes the crates defend against

#### Phase 3: ZAP Alert Baseline

Create `scripts/zap-baseline.json` — expected findings that are **false positives** or **accepted risks**:

- Dev-only headers (`X-Dev-Subject`) — will trigger header injection warnings
- In-memory storage — no real DB to trigger SQL injection
- Accepted: informational findings about HTTP methods, CORS

#### Phase 4: CI Integration

Add to GitHub Actions workflow:

```yaml
zap-scan:
  needs: [build, test]
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - name: Build smoke service
      run: cargo build -p secure_smoke_service
    - name: Start service
      run: cargo run -p secure_smoke_service &
    - name: Run ZAP API scan
      uses: zaproxy/action-api-scan@v0.9.0
      with:
        target: http://localhost:3000/openapi.yaml
        rules_file_name: scripts/zap-rules.tsv
        fail_action: true
    - name: Upload ZAP report
      uses: actions/upload-artifact@v4
      with:
        name: zap-report
        path: report_html.html
```

### 10.3 Expected ZAP Findings vs Controls

| ZAP Alert | Expected Result | Control |
|---|---|---|
| Cross-Site Scripting (Reflected) | **PASS** — `HtmlEncoder` prevents | `secure_output` |
| SQL Injection | **PASS** — no SQL in smoke service; `SafeIdentifier` type for real apps | `secure_boundary` |
| Path Traversal | **PASS** — `SafePath` rejects `../` | `secure_boundary` |
| Remote OS Command Injection | **PASS** — `SafeCommandArg` rejects metachar | `secure_boundary` |
| CRLF Injection | **PASS** — header sanitisation | `secure_boundary` |
| Missing Security Headers | **PASS** — `SecurityHeadersLayer` | `secure_boundary` |
| Cookie Without Secure Flag | **N/A** — no cookies in default config | — |
| Information Disclosure (Error) | **PASS** — `secure_errors` prevents leakage | `secure_errors` |
| XML External Entity (XXE) | **PASS** — `SecureXml` extractor | `secure_boundary` |
| Server-Side Request Forgery | **PASS** — `SafeUrl` validates | `secure_boundary` |
| CSP Header Not Set | **PASS** — present | `secure_boundary` |
| X-Frame-Options Not Set | **PASS** — `DENY` | `secure_boundary` |

### 10.4 ZAP Custom Scan Rules

Write ZAP scan rules (`scripts/zap-rules.tsv`) that:

- Increase confidence threshold for SQLi (no DB = false positives expected)
- Enable all XSS passive/active rules at maximum strength
- Enable CRLF injection checks
- Enable path traversal checks with `../` depth up to 10
- Test `X-Dev-Subject` header injection (should be caught)

---

## 11. Supply-Chain & CI Improvements

| # | Feature | Description | Priority |
|---|---|---|---|
| 1 | **SBOM generation** | Generate CycloneDX or SPDX SBOM on every release via `cargo-cyclonedx` | High |
| 2 | **Container image scanning** | If Docker images are published, scan with Trivy/Grype in CI | Medium |
| 3 | **Dependency update automation** | Renovate or Dependabot for automated dependency PRs | Medium |
| 4 | **cargo-vet audit progress** | Systematically audit exempted dependencies (248 at bootstrap) — target 50% audited | Medium |
| 5 | **Binary reproducibility** | Verify reproducible builds via `cargo-reproducible` or hash comparison | Low |

---

## 12. Prioritized Build Plan

### Milestone 11: Security Smoke Service + Safe Types (Critical)

| # | Item | Crate | Effort |
|---|---|---|---|
| 11.1 | `SafePath`, `SafeFilename`, `SafeCommandArg` safe types | `secure_boundary` | Medium |
| 11.2 | `SafeUrl`, `SafeRedirectUrl` safe types | `secure_boundary` | Medium |
| 11.3 | `SqlIdentifier`, `LdapSafeString` safe types | `secure_boundary` | Small |
| 11.4 | Enforce `max_nesting_depth` in `SecureJson` | `secure_boundary` | Small |
| 11.5 | Enforce `max_field_count` in `SecureJson` | `secure_boundary` | Small |
| 11.6 | `sanitize_header_value()` for CRLF prevention | `secure_boundary` | Small |
| 11.7 | `SecureXml` extractor (XXE prevention) | `secure_boundary` | Medium |
| 11.8 | `JsStringEncoder`, `CssEncoder`, `XmlEncoder` | `secure_output` | Medium |
| 11.9 | `sanitize_uri_scheme()` protocol allowlist | `secure_output` | Small |
| 11.10 | `secure_smoke_service` crate with all routes above | New crate | Large |
| 11.11 | Smoke test suite (integration tests for every attack class) | `secure_smoke_service` | Large |
| 11.12 | OpenAPI spec for smoke service | `secure_smoke_service` | Medium |

### Milestone 12: Real Provider Integrations (Critical)

| # | Item | Crate | Effort |
|---|---|---|---|
| 12.1 | `VaultKeyProvider` (HashiCorp Vault Transit) | `secure_data` | Large |
| 12.2 | `AwsKmsKeyProvider` (AWS KMS) | `secure_data` | Large |
| 12.3 | `AzureKeyVaultProvider` (Azure Key Vault) | `secure_data` | Large |
| 12.4 | `resolve_secret()` function for `SecretReference` | `secure_data` | Medium |
| 12.5 | Persistent `KeyRingStore` trait + file/DB impls | `secure_data` | Medium |
| 12.6 | RS256/ES256 JWT validation | `secure_identity` | Medium |
| 12.7 | JWKS endpoint fetch + key rotation cache | `secure_identity` | Medium |
| 12.8 | OIDC Discovery (`.well-known/openid-configuration`) | `secure_identity` | Medium |
| 12.9 | `RedisSessionManager` | `secure_identity` | Medium |
| 12.10 | `ApiKeyAuthenticator` | `secure_identity` | Medium |

### Milestone 13: ZAP Integration + Authz Hardening (High)

| # | Item | Crate | Effort |
|---|---|---|---|
| 13.1 | OWASP ZAP scan script (`scripts/zap_scan.sh`) | Scripts | Medium |
| 13.2 | ZAP configuration + alert baseline | Scripts | Small |
| 13.3 | ZAP CI integration (GitHub Actions) | CI | Medium |
| 13.4 | ZAP custom scan rules | Scripts | Small |
| 13.5 | Fix `CacheKey` to include `tenant_id` | `secure_authz` | Small |
| 13.6 | Obligation enforcement in `AuthzLayer` middleware | `secure_authz` | Medium |
| 13.7 | Policy hot-reload (file watcher or API) | `secure_authz` | Medium |
| 13.8 | Auto-mapping error middleware | `secure_errors` | Medium |
| 13.9 | Error context propagation (task-local) | `secure_errors` | Medium |
| 13.10 | `Retry-After` header for rate-limited responses | `secure_errors` | Small |

### Milestone 14: Observability + Advanced Features (Medium)

| # | Item | Crate | Effort |
|---|---|---|---|
| 14.1 | HMAC-signed audit chain entries | `security_events` | Medium |
| 14.2 | Additional sinks (File, Syslog, HTTP webhook) | `security_events` | Medium |
| 14.3 | Async batched event emission | `security_events` | Medium |
| 14.4 | Distributed tracing middleware (auto trace_id) | `security_events` | Medium |
| 14.5 | TOTP MFA implementation | `secure_identity` | Medium |
| 14.6 | Row-level security helpers | `secure_authz` | Large |
| 14.7 | Bulk authorization for list endpoints | `secure_authz` | Medium |
| 14.8 | SBOM generation in CI | CI | Small |
| 14.9 | Cross-Origin headers (COEP, COOP, CORP) | `secure_boundary` | Small |
| 14.10 | Nonce-based CSP support | `secure_boundary` | Medium |

---

## Appendix A: Attack-Class Coverage Matrix (Current vs Proposed)

| Attack Class | OWASP Top 10 | Current Coverage | After M11 | Validated By |
|---|---|---|---|---|
| Cross-Site Scripting (XSS) | A03:2021 | ✅ Output encoding (HTML, URL, JSON) | ✅ + JS, CSS encoding | ZAP + smoke tests |
| SQL Injection | A03:2021 | ❌ Not addressed | ✅ `SqlIdentifier` safe type | Smoke tests |
| OS Command Injection | A03:2021 | ❌ Not addressed | ✅ `SafeCommandArg` type | Smoke tests |
| Path Traversal | A01:2021 | ❌ Not addressed | ✅ `SafePath` type | ZAP + smoke tests |
| XXE | A05:2021 | ❌ Not addressed | ✅ `SecureXml` extractor | ZAP + smoke tests |
| Insecure Deserialization | A08:2021 | ✅ Strict serde, unknown fields | ✅ + depth/field limits enforced | Smoke tests |
| Mass Assignment | A01:2021 | ✅ Unknown fields rejected | ✅ No change needed | Smoke tests |
| CRLF / Header Injection | — | ❌ Partial (events only) | ✅ `sanitize_header_value()` | ZAP + smoke tests |
| SSRF | A10:2021 | ❌ Not addressed | ✅ `SafeUrl` type | Smoke tests |
| Open Redirect | — | ❌ Not addressed | ✅ `SafeRedirectUrl` type | ZAP + smoke tests |
| LDAP Injection | A03:2021 | ❌ Not addressed | ✅ `LdapSafeString` type | Smoke tests |
| Log Injection | — | ✅ `sanitize_for_text_sink()` | ✅ No change needed | Smoke tests |
| JSON Bomb / DoS | — | ⚠️ Size limit only, depth/field unenforced | ✅ Depth + field count enforced | Smoke tests |
| Token Replay | A07:2021 | ✅ Expiration enforcement | ✅ No change needed | Smoke tests |
| Broken Authentication | A07:2021 | ⚠️ HS256 JWT only | ✅ RS256/ES256, JWKS, OIDC | Smoke tests |
| Broken Access Control | A01:2021 | ✅ RBAC, tenant isolation | ✅ + cache fix, obligations | Smoke tests |
| Sensitive Data Exposure | A02:2021 | ✅ Envelope encryption, Secret types | ✅ + real KMS/Vault | Smoke tests |
| Security Misconfiguration | A05:2021 | ✅ Security headers, fail-fast config | ✅ + COEP/COOP/CORP | ZAP passive scan |

## Appendix B: File Structure for New Crates

```
crates/
  secure_smoke_service/
    Cargo.toml
    openapi.yaml
    src/
      main.rs              # Service entrypoint
      lib.rs               # build_router() for tests
      routes/
        input.rs           # /smoke/xss, /smoke/sqli, /smoke/cmdi, etc.
        output.rs          # /smoke/reflect-html, /smoke/reflect-url, etc.
        auth.rs            # /smoke/auth/* routes
        authz.rs           # /smoke/authz/* routes
        data.rs            # /smoke/encrypt, /smoke/decrypt, etc.
        errors.rs          # /smoke/error/* routes
        events.rs          # /smoke/events/* routes
      state.rs             # AppState with real providers
      config.rs            # SecurityConfig for smoke service
    tests/
      smoke_tests.rs       # Full attack-class integration tests
      zap_baseline.rs      # ZAP finding baseline assertions

  secure_boundary/src/
    safe_types.rs          # SafePath, SafeFilename, SafeCommandArg, etc.
    xml.rs                 # SecureXml extractor

  secure_output/src/
    js.rs                  # JsStringEncoder
    css.rs                 # CssEncoder
    xml.rs                 # XmlEncoder

  secure_data/src/
    providers/
      mod.rs
      vault.rs             # VaultKeyProvider
      aws_kms.rs           # AwsKmsKeyProvider
      azure_kv.rs          # AzureKeyVaultProvider
    resolve.rs             # resolve_secret() implementation
    store.rs               # KeyRingStore trait + impls
```
