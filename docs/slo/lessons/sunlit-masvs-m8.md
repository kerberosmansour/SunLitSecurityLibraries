# Lessons Learned — sunlit-masvs Milestone 8

## What changed
- Added 15 mobile security smoke routes under `/smoke/mobile/` to `secure_smoke_service`
- Each route exercises exactly one MASVS control area (NETWORK, STORAGE, AUTH, PLATFORM, RESILIENCE, PRIVACY)
- Created `mobile_routes.rs` module with route handlers
- Updated `openapi.yaml` with 15 new path entries and 15 new request schemas
- Updated DAST index HTML with mobile route forms
- Total route count: 39 → 54

## Design decisions and why
- **No auth middleware on mobile routes**: Matching existing pattern where smoke routes don't require JWT auth — they test the security controls themselves, not authentication. Auth is tested via `/smoke/auth/*` routes.
- **Direct JSON parsing instead of `SecureJson`**: Mobile routes accept `axum::Json` directly because they need to parse custom DTOs with fields specific to each control. The `SecureJson` extractor requires `SecureValidate` impl which would add ceremony without security value for smoke test routes that already validate input via the security crate APIs.
- **PinSet::matches for cert-pin route**: Cannot construct synthetic DER certificates that hash to a specific SPKI hash, so the cert-pin route uses `PinSet::matches` directly to prove pin validation works. This tests the core control path.
- **String-based TLS version parsing**: `TlsVersion` enum has `Serialize` but not `Deserialize`, so a manual `parse_tls_version` function maps string inputs to enum variants.
- **InMemorySink for event verification**: Routes that emit security events (root-detect, app-integrity, consent) use `InMemorySink` and return `events_emitted` count so E2E tests can verify event emission without accessing global state.

## Mistakes made
- First attempt included redundant `PinSet` construction and an unused `CertPinValidator` variable in `cert_pin_check` — cleaned up after compiler warning.
- Initially used `Serialize` derive on `JsonResponse` struct that was never used — removed.
- Non-exhaustive enum matches for `PiiClassification` and `ConsentDecision` needed wildcard arms.

## Root causes
- `PiiClassification` and `ConsentDecision` are marked `#[non_exhaustive]` in their crate, requiring `_` arms even when all variants are matched.
- Assumed `CertPinValidator` had a `pin_set_matches` method — it doesn't; `PinSet::matches` is the correct API.

## What was harder than expected
- Nothing notably difficult — the API surface was well-designed and the existing route patterns were easy to follow.

## Naming conventions established
- Module: `mobile` (under `routes/`)
- Route prefix: `/smoke/mobile/`
- Response codes: descriptive snake_case (`tls_version_rejected`, `pin_valid`, `cleartext_blocked`)
- DTOs: `<Control>Request` (e.g., `TlsVersionRequest`, `CertPinRequest`)

## Test patterns that worked well
- `json_post` helper for concise test requests
- Parameterized route arrays in `test_all_mobile_routes_respond` and `test_attack_payloads_rejected`
- Checking `events_emitted` count in response JSON to verify security event emission

## Missing tests that should exist now
- Fuzz targets for mobile route payloads (deferred to M9)
- Property tests: "no TLS version below 1.2 passes validation" (deferred to M9)
- Load testing for mobile routes

## Rules for the next milestone
- M9 adds adversarial testing (fuzz, property tests, CVE regression) — production code should not change
- Mobile routes are stateless and do not require AppState — keep them simple
- When adding fuzz targets for mobile controls, target the underlying crate APIs, not the HTTP layer

## Template improvements suggested
- Consider adding a "Dependencies added" section to the completion summary template
