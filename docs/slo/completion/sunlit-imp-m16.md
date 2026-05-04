# Completion Summary — M16: Security Smoke-Test Microservice

## Milestone Goal

Create `crates/secure_smoke_service/` — a purpose-built axum microservice with 35+ routes, each exercising a specific security control against a known attack class.

## Deliverables

| Deliverable | Status | Notes |
|---|---|---|
| `crates/secure_smoke_service/Cargo.toml` | ✅ | Workspace member, all 8 library crate deps + jsonwebtoken |
| `src/config.rs` | ✅ | `SecurityConfig` with `dev()` constructor |
| `src/state.rs` | ✅ | `AppState` with TokenValidator, Authorizer, KeyRing, SessionManager |
| `src/routes/input.rs` | ✅ | 12 input validation routes |
| `src/routes/output.rs` | ✅ | 4 output encoding routes |
| `src/routes/auth.rs` | ✅ | 6 authentication routes |
| `src/routes/authz.rs` | ✅ | 5 authorization routes |
| `src/routes/data.rs` | ✅ | 5 data protection routes |
| `src/routes/errors.rs` | ✅ | 4 error handling routes |
| `src/routes/events.rs` | ✅ | 2 security events routes |
| `src/lib.rs` | ✅ | `build_router()` with middleware stack |
| `src/main.rs` | ✅ | Binary entrypoint on port 3001 |
| `tests/smoke_tests.rs` | ✅ | 40 BDD tests (all pass) |
| `tests/e2e_sunlit_imp_m16.rs` | ✅ | 10 acceptance scenario tests (all pass) |
| `openapi.yaml` | ✅ | OpenAPI 3.1 spec for OWASP ZAP |
| `ARCHITECTURE.md` | ✅ | Smoke service section added |
| `README.md` | ✅ | Route table, running instructions added |

## Route Count

39 routes total (target was 35+):
- Input validation: 12
- Output encoding: 4
- Authentication: 6
- Authorization: 5
- Data protection: 5
- Error handling: 4
- Security events: 2
- Health: 1

## Test Results

- `cargo test -p secure_smoke_service`: 50 tests (40 smoke + 10 e2e), 0 failures
- `cargo test --workspace`: all pass, 0 regressions
- `cargo clippy --workspace --all-targets -- -D warnings`: clean

## Attack Classes Covered

| # | Attack Class | Route | Control |
|---|---|---|---|
| 1 | XSS | `/smoke/xss` | `HtmlEncoder` |
| 2 | SQL injection | `/smoke/sqli` | `SqlIdentifier` |
| 3 | Command injection | `/smoke/cmdi` | `SafeCommandArg` |
| 4 | Path traversal | `/smoke/path-traversal/*` | `SafePath` |
| 5 | XXE | `/smoke/xxe` | `SecureXml` DOCTYPE scan |
| 6 | Deserialization | `/smoke/deserialization` | `SecureJson` deny_unknown_fields |
| 7 | Mass assignment | `/smoke/mass-assignment` | `SecureJson` deny_unknown_fields |
| 8 | CRLF injection | `/smoke/header-injection` | `sanitize_header_value()` |
| 9 | Unicode bypass | `/smoke/unicode-bypass` | NFC normalisation |
| 10 | Body bomb | `/smoke/body-bomb` | 1 MiB body limit |
| 11 | Deep nesting | `/smoke/deep-nesting` | `max_nesting_depth` |
| 12 | Field flood | `/smoke/field-flood` | `max_field_count` |
| 13 | Reflected XSS (HTML) | `/smoke/reflect-html` | `HtmlEncoder` |
| 14 | Open redirect | `/smoke/reflect-url` | `sanitize_uri_scheme()` |
| 15 | Script injection | `/smoke/reflect-json` | `JsonEncoder` |
| 16 | Missing headers | `/smoke/headers` | `SecurityHeadersLayer` |
| 17 | Invalid JWT | `/smoke/auth/jwt` | `TokenValidator` |
| 18 | Expired JWT | `/smoke/auth/expired` | expiry validation |
| 19 | alg:none (CVE-2015-9235) | `/smoke/auth/alg-none` | algorithm enforcement |
| 20 | Tampered JWT | `/smoke/auth/tampered` | signature validation |
| 21 | Wrong issuer | `/smoke/auth/wrong-issuer` | issuer validation |
| 22 | Session fixation | `/smoke/auth/session` | `InMemorySessionManager` |
| 23 | Missing permissions | `/smoke/authz/allow` | `DefaultAuthorizer` |
| 24 | Role escalation | `/smoke/authz/deny` | deny-by-default |
| 25 | Cross-tenant | `/smoke/authz/cross-tenant` | tenant isolation |
| 26 | Privilege escalation | `/smoke/authz/privilege-escalation` | policy engine |
| 27 | IDOR | `/smoke/authz/idor` | resource ownership |
| 28 | Plaintext leak | `/smoke/encrypt` | envelope encryption |
| 29 | Ciphertext swap | `/smoke/decrypt` | AEAD authentication |
| 30 | Tampered ciphertext | `/smoke/decrypt-tampered` | AEAD tag check |
| 31 | Secret in logs | `/smoke/secret-debug` | `SecretString` redaction |
| 32 | Key rotation gap | `/smoke/key-rotation` | `KeyRing` rotation |
| 33 | Stack trace leak | `/smoke/error/internal` | `AppError` → safe codes |
| 34 | Hostname leak | `/smoke/error/dependency` | generic error mapping |
| 35 | Panic info leak | `/smoke/error/panic` | `CatchPanicLayer` |
| 36 | Verbose errors | `/smoke/error/validation` | `AppError::Validation` |
| 37 | Log injection | `/smoke/events/log-injection` | structured logging |
| 38 | PII in logs | `/smoke/events/redaction` | event field sanitisation |
| 39 | Health | `/health` | availability check |
