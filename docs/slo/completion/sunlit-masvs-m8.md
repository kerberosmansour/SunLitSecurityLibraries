# Completion Summary — sunlit-masvs Milestone 8

## Goal completed
- Added 15 mobile security smoke test routes to `secure_smoke_service`, one per MASVS control area
- All routes serve as DAST targets via updated OpenAPI spec
- Total smoke service routes: 39 → 54

## Files changed
- `crates/secure_smoke_service/Cargo.toml` — added `secure_network`, `secure_resilience`, `secure_privacy` deps; enabled `mobile-storage`, `biometric`, `mobile-platform` features
- `crates/secure_smoke_service/src/routes/mod.rs` — added `pub mod mobile`
- `crates/secure_smoke_service/src/lib.rs` — wired 15 mobile routes into router, updated DAST index HTML
- `crates/secure_smoke_service/openapi.yaml` — added 15 path entries and 15 request schemas
- `ARCHITECTURE.md` — updated route table from 39 to 54 routes with mobile categories
- `README.md` — updated route count and mobile coverage description

## Tests added
- `crates/secure_smoke_service/tests/e2e_sunlit_masvs_m8.rs` — 12 tests total

## Runtime validations added
- `test_all_mobile_routes_respond` — all 15 mobile routes respond with expected status codes
- `test_mobile_routes_require_valid_json` — all 15 routes reject invalid JSON
- `test_attack_payloads_rejected` — 7 attack payloads across TLS, deep-link, webview, cleartext, step-up, integrity, consent
- `test_security_events_emitted` — root-detect and app-integrity emit security events

## BDD scenarios validated
- `bdd_tls_version_rejects_tls10` — TLS 1.0 rejected with `tls_version_rejected`
- `bdd_cert_pin_validates_known_hash` — known hash returns `pin_valid`
- `bdd_deep_link_validates_safe_url` — `myapp://profile/1` returns `valid_deep_link`
- `bdd_deep_link_rejects_javascript_scheme` — `javascript:alert(1)` returns `dangerous_scheme`
- `bdd_pii_classifier_detects_email` — email classified as `email`
- `bdd_pseudonymizer_returns_consistent_hash` — same input+salt produces same output
- `bdd_root_detection_signal_processed` — root signal returns RASP decision
- `bdd_existing_health_route_works` — `/health` still returns 200 OK

## New files
- `crates/secure_smoke_service/src/routes/mobile.rs`
- `crates/secure_smoke_service/tests/e2e_sunlit_masvs_m8.rs`

## New routes (15)
| Route | MASVS Control |
|---|---|
| `/smoke/mobile/tls-version` | MASVS-NETWORK-1 |
| `/smoke/mobile/cert-pin` | MASVS-NETWORK-1 |
| `/smoke/mobile/cleartext` | MASVS-NETWORK-2 |
| `/smoke/mobile/storage-policy` | MASVS-STORAGE-1 |
| `/smoke/mobile/sensitive-buffer` | MASVS-STORAGE-1 |
| `/smoke/mobile/biometric` | MASVS-AUTH-2 |
| `/smoke/mobile/step-up` | MASVS-AUTH-3 |
| `/smoke/mobile/deep-link` | MASVS-PLATFORM-1 |
| `/smoke/mobile/webview-url` | MASVS-PLATFORM-1 |
| `/smoke/mobile/clipboard` | MASVS-PLATFORM-2 |
| `/smoke/mobile/root-detect` | MASVS-RESILIENCE-1 |
| `/smoke/mobile/app-integrity` | MASVS-RESILIENCE-2 |
| `/smoke/mobile/pii-classify` | MASVS-PRIVACY-1 |
| `/smoke/mobile/pseudonymize` | MASVS-PRIVACY-2 |
| `/smoke/mobile/consent` | MASVS-PRIVACY-3 |
