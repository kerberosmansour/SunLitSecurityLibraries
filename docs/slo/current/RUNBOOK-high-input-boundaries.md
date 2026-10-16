---
id: high-input-boundaries
prefix: high-input-boundaries
version: 4
stack: Rust
ai_component: false
baseline: cargo test -p secure_output --locked && cargo test -p secure_boundary --all-features --locked
---
# High-risk input boundary repairs — confirmed M1

Eliminate the three high-severity findings in merged-main Codex Security run
`wfr_4a87ac67ebc4b17474ac10c6cb2ba50ae1f4afbe190f6ccf6e66c9d65290a8db`
at `379efff4255674ad755654b64dde086066802218`: browser-normalized URI/XSS
bypasses, post-allocation request limits, and SafeUrl parser differentials.
This is one bounded source-and-documentation milestone. Publication and version
changes remain a later contract.

## Contract

- `sanitize_uri_scheme` remains source compatible, but accepts only explicit
  `http`, `https`, and `mailto` schemes or well-formed relative references. It
  rejects C0/DEL controls, browser whitespace, backslashes, HTML attribute
  delimiters and ambiguous schemes. Documentation must HTML-attribute encode the
  accepted value at the sink; URI validation alone is never described as encoding.
- Axum JSON and XML extractors share a streaming byte cap backed by Axum's
  `body::to_bytes(body, limit)`. Both honor the request's `RequestLimits`
  extension. Limit overflow emits `BodyTooLarge`; transport failure remains
  `MalformedBody`. A declared `Content-Length` larger than the cap may fail early,
  but chunked bodies are still bounded by the collector.
- `SafeUrl` parses once with the existing locked `url` crate, rejects any
  credentials, backslash, fragment, missing host, non-HTTP(S) scheme, and
  non-public parsed IP, and stores the parser's canonical serialization. Decimal,
  shortened and octal-like IPv4 spellings cannot fall through as domain names.
  Literal and resolved addresses share a conservative public-unicast policy that
  rejects carrier-grade/provider-metadata, documentation, benchmarking, reserved
  and IPv6 special-purpose ranges. `SafeRedirectUrl` resolves against a fixed
  HTTPS origin, retains the canonical relative reference, and rejects raw or
  encoded path-separator/control differentials.
  DNS rebinding remains a documented residual: consumers must classify every
  resolved address and pin the approved address through connection establishment.
- No new external dependency identity is admitted. Making the already locked
  `url` package a direct dependency requires build-free exact lock resolution,
  publisher/source/checksum and lifecycle review, full graph diff, and official
  pinned OSV/MAL scanning of every lock before any build, macro, test or script.

Data classification: attacker-controlled URLs and request bodies are
Confidential at most; credentials and fetched response data remain Restricted.
Proactive controls: C3 Validate all Input & Handle Exceptions, C4 Address
Security from the Start, C5 Secure by Default, C7 Enforce Access Controls, and
C9 Implement Security Logging and Monitoring. AI tolerance: N/A — no AI
component. Measurement: N/A — corrective security maintenance, with removal of
three exact findings as the observable result. UI/design: N/A.

## Threat and outcome contract

Threat model: `docs/slo/design/high-input-boundaries-threat-model.md`.

- `oc-high-input-boundaries-1` / `cuj-high-input-boundaries-1`: hostile URI text
  cannot become an executable or attribute-breaking browser URL when the
  documented validator-plus-encoder composition is used.
- `oc-high-input-boundaries-2` / `cuj-high-input-boundaries-2`: JSON and XML
  requests crossing the configured byte cap stop at the cap and return the fixed
  oversized-body rejection before parser allocation.
- `oc-high-input-boundaries-3` / `cuj-high-input-boundaries-3`: every known
  alternate numeric/backslash URL witness and non-public literal/resolver answer
  is rejected before a consumer can issue a request; same-origin redirects cannot
  become network paths under downstream normalization.

BDD begins with failing public-API regressions for the scan witnesses. Negative
controls cover normal absolute and relative links, public canonical IPs, ordinary
JSON/XML bodies and request-specific limits. Existing URI, SafeUrl, XML and JSON
suites must remain green. Core regression matrix: secure_output URI API = pass;
secure_boundary SafeUrl = pass; axum JSON/XML = pass; actix JSON = pass;
workspace crates = pass; browser live UI, cloud, AI and physical device =
not_applicable because this milestone introduces none.

TLA and Kani: N/A. The work composes existing deterministic parsers/collectors and
adds no protocol, state machine, crypto primitive or bounded algorithm needing a
formal harness. Runtime witnesses and variant analysis are the stronger evidence.

## M1 exact allow-list (21)

- `Cargo.lock`
- `crates/secure_boundary/Cargo.toml`
- `crates/secure_boundary/src/extract.rs`
- `crates/secure_boundary/src/xml.rs`
- `crates/secure_boundary/src/safe_types.rs`
- `crates/secure_boundary/tests/codex_security_input_boundaries.rs`
- `crates/secure_output/src/uri.rs`
- `crates/secure_output/tests/codex_security_uri.rs`
- `crates/secure_output/README.md`
- `docs/dev-guide/secure-output.md`
- `docs/dev-guide/safe-url-ssrf.md`
- `docs/dev-guide/secure-boundary.md`
- `README.md`
- `ARCHITECTURE.md`
- `CHANGELOG.md`
- `docs/slo/current/RUNBOOK-high-input-boundaries.md`
- `docs/slo/design/high-input-boundaries-threat-model.md`
- `docs/slo/critique/high-input-boundaries-m1.md`
- `docs/slo/verify/high-input-boundaries-m1.md`
- `docs/slo/lessons/high-input-boundaries-m1.md`
- `docs/slo/completion/high-input-boundaries-m1.md`

Exemplars: exact locked `url` 2.x parser already used by `secure_identity`, Axum
0.8 `body::to_bytes`, `HtmlEncoder`'s `OutputEncoder::encode`, current fixed
`BoundaryRejection` mapping, and per-CIDR SafeUrl tests. Anti-exemplars: raw
scheme blocklists, post-collection size checks, manual authority splitting,
reusing an accepted raw string, or describing string validation as DNS/connect
pinning. Abuse acceptance scenarios are the three threat-model rows; no new
surface is introduced.

Forbidden shortcuts: new parser code, raw HTML interpolation, swallowing body
limit errors, accepting credentials/fragments/backslashes, treating parse failure
as a hostname, compiling before admission, OSV/MAL waivers, fabricated audits,
scope widening, or claiming DNS rebinding is solved.

## Evidence log

| Check | Actual result |
|---|---|
| Readiness/baseline | Base `379efff4255674ad755654b64dde086066802218`; focused package baselines passed before production edits. |
| Red scan-witness regressions | URI suite failed 2 hostile cases; boundary suite failed all 5 original witnesses for full collection, ignored XML request limits, parser differentials and raw-value retention. |
| Candidate exact lock/provenance/OSV | Script-disabled offline resolution retained 514 package identities. Existing locked `url` 2.5.8 archive matched checksum and declared `build = false`; crates.io owners/source/license reviewed. Official OSV 2.7.0 scanned 6 locks/1,448 package occurrences: 4 existing reviewed advisories, 0 `MAL-*`, exit 0. JSON SHA-256 `6cea97a78ce4454665abdde3ede39bbd5f76050c30914613c59f1de2a4053ed0`. |
| Focused production and variant tests | URI 3/3 and corrective input boundaries 10/10 passed; secure_output and secure_boundary package/doc suites passed; secure_boundary none/axum/actix/both feature matrix passed. |
| Workspace/static/docs/scope | Default and all-feature locked workspace suites, all-feature Clippy, zero-warning rustdoc and fmt passed. Cargo audit found 0 unaccepted vulnerabilities; deny and vet passed. Semgrep production/secrets found 0 findings/errors. Diff check and exact allow-list passed. |
| Exact-head CI and merged-main Codex Security | PR #149 passed and merged as `f76711797c37799e4d0d3b1883d758e90711175d`. Its scan found carrier-grade/provider-metadata acceptance and a redirect normalization gap. Corrective PR #150 then passed all 33 exact-head checks and merged as GitHub-verified, DCO-signed `6b99e38528ceba765a341ee54a6e2687e7607d4e`; parent `f76711797c37799e4d0d3b1883d758e90711175d`, tree `9594a5537eaf49b1debf9861a4ff24ee26d905c9`, byte-identical to reviewed head `b6ebb3b62e9ba0611355ea463cb661bc00dffdc4`. Exact merged-main run `wfr_ba7e824e52f38743230cf3f9760ae39f61250e26e08e52cf854358c2cb7e3e51` completed with 27 findings (10 medium, 17 low), 0 critical/high, and neither corrective finding class. Report SHA-256 `edcde530a644cc2408bd22276e873afca9c4a07d3c935b8184f722778885e50d`. |
| Verify/retro/closure | Verification, lessons and completion handoff record the initial implementation, corrective red/green cycle, exact-head CI, immutable merge identity and complete merged-main report. M1 is complete; remaining repository findings are separate severity-ordered milestones. |

## Milestone tracker

| Milestone | Status | Started | Finished |
|---|---|---|---|
| M1 high-severity input-boundary repairs and scan follow-up | done | 2026-10-16 | 2026-10-16 |

The user's standing instruction to continue autonomously and publish when needed
is the confirmation basis for this concrete milestone and allow-list.
