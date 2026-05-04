---
topic: # Idea — Take SunLit Security Libraries Public as Mission-Critical OSS  **Slug:** `oss-public-release` **Created:** 2026-04-25 **Status:** Pre-research — feeds `/slo-research` then `/slo-plan` **Pointer…
generated_on: 2026-04-25 23:32:20 +0100
source_prompt_bytes: 7056
generator: sldo-research
---

# Research Dossier

This dossier is a structured research artifact produced by `sldo-research`. It is intended as the `prompt_file` input to `sldo-plan`.

## Repository Context

I have enough context now to compose the report.

## Tech Stack

- **Language**: Rust, edition 2021. No `rust-toolchain.toml` or per-crate `rust-version`/MSRV declared; CI pins `dtolnay/rust-toolchain@stable` plus nightly-only fuzz/miri commands.
- **Workspace**: 13 member crates under `[workspace] resolver = "2"`. All members are `version = "0.1.0"`, `license = "MIT"`.
- **Async runtime**: `tokio = "1"` (workspace dep, `features = ["full"]`); per-crate trims to `sync`/`time`/`rt`.
- **HTTP / web**: `axum = "0.8"` + `axum-core = "0.5"`, `tower = "0.5"`, `tower-http = "0.6"`, `hyper = "1"`, `http = "1"`. Optional `actix-web = "4"` adapters in `secure_authz`, `secure_boundary`, `secure_errors`.
- **Crypto / security**: `aes-gcm`, `chacha20poly1305`, `ring`, `subtle`, `secrecy`, `zeroize`, `argon2` (feature), `aws-lc-rs` (FIPS feature), `jsonwebtoken = "9"`, `totp-rs = "5"`, `openidconnect = "4"` (feature), `casbin = "2"`.
- **Cloud / KMS (feature-gated)**: `aws-sdk-kms`, `aws-config`, `reqwest = "0.12"` (rustls-tls), `redis = "1"`.
- **Observability / utilities**: `tracing`, `tracing-subscriber`, `serde`, `serde_json`, `thiserror`, `derive_more`, `uuid`, `time = "0.3"`, `smallvec`, `lru = "0.12"`, `sha2`, `base64`, `url`, `proptest`.

## Project Structure

- `crates/` — 13-member workspace; each crate maps to an OWASP Proactive Control:
  - `security_core` — shared types, `IdentitySource` trait, classifications, redaction (no I/O).
  - `secure_errors` — three-layer error model (`AppError` / `PublicError` / `ErrorClassification`), axum + actix adapters, panic boundary.
  - `security_events` — telemetry, HMAC-sealed events, NDJSON/file/batched sinks, AppSensor detection, log-injection sanitization.
  - `secure_boundary` — input validation, `SecureJson`/`SecureXml` extractors, safe types, security headers, CORS, Fetch Metadata, html sanitization.
  - `secure_output` — context-aware encoders (HTML, URL, JS, CSS, XML, LDAP, shell), URI scheme guard.
  - `secure_identity` — JWT/OIDC, TOTP MFA, sessions, biometric/step-up auth (feature-gated).
  - `secure_authz` — deny-by-default policy engine (Casbin), RBAC + ABAC + temporal, axum/actix middleware.
  - `secure_data` — secret types, envelope encryption, KMS (Vault/AWS KMS/Azure KV), Argon2id, mobile storage.
  - `secure_network` — TLS policy, SPKI cert pinning, cleartext detection.
  - `secure_resilience` — RASP-style resilience signals.
  - `secure_privacy` — PII classifier and pseudonymization.
  - `secure_reference_service` — axum reference binary composing all eight library crates (port 3000).
  - `secure_smoke_service` — 54-route DAST smoke target (incl. 15 mobile MASVS routes).
  - Multiple crates carry sibling `fuzz/` directories (cargo-fuzz targets).
- `docs/` — `attack-trees/`, `dev-guide/` (one guide per crate + integration + production checklist), `lessons/`, `completed-runbooks/`, `completion/`, `oss-public-release/`, `idea/`, `research/`.
- `scripts/` — `audit.sh` / `audit.ps1` (cargo-audit + deny + vet runners), `dastardly_scan.sh`, `run_zap_local.sh`, `zap_scan.sh`, `zap_check.py`, `zap_hooks.py`.
- `supply-chain/` — `audits.toml`, `config.toml`, `imports.lock` for `cargo-vet`.
- `.cargo/audit.toml`, `deny.toml` — RustSec advisory ignore list mirrored across both tools with written justifications.
- `.github/workflows/` — `ci.yml`, `dastardly.yml`, `zap.yml`.
- Root docs: `ARCHITECTURE.md` (52 KB), `THREAT_MODEL.md` (57 KB), `README.md` (31 KB).
- `target/`, `output/`, `.copilot-logs/`, `.sldo-logs/` — build/log artifacts (not source).

## Build & Test

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo doc --workspace --no-deps          # CI also runs --all-features with RUSTDOCFLAGS="-D warnings"

# Targeted suites (filter conventions in CI/README)
cargo test --workspace --test 'e2e_*'
cargo test --workspace -- prop_
cargo test --workspace -- cve_
cargo test --workspace -- timing_ --ignored

# Supply chain
bash scripts/audit.sh                    # cargo audit && cargo deny check && cargo vet
pwsh scripts/audit.ps1                   # Windows equivalent

# Nightly-only
cargo +nightly miri test --workspace
cargo install cargo-fuzz
cd crates/<crate> && cargo +nightly fuzz run <target> -- -max_total_time=60

# Reference & smoke services
cargo run -p secure_reference_service    # 127.0.0.1:3000
cargo run -p secure_smoke_service        # DAST target
```

CI matrix (`.github/workflows/ci.yml`): runs on `ubuntu-latest`, `macos-latest`, `windows-latest`. A `feature-matrix` job re-runs `cargo check`/`cargo test` for `secure_boundary`, `secure_authz`, `secure_errors` across `""`, `axum`, `actix-web`, `axum actix-web` feature sets to prevent backsliding. A `rustdoc-warnings` job builds docs with `--all-features` and `RUSTDOCFLAGS="-D warnings"`. `supply-chain` job installs and runs `cargo audit`, `cargo deny check`, `cargo vet`. Separate `dastardly.yml` and `zap.yml` workflows run DAST against `secure_smoke_service`.

## Existing Patterns

- **Module hygiene**: every library crate's `lib.rs` opens with `#![forbid(unsafe_code)]`, most also `#![deny(missing_docs)]`; `secure_errors` adds `#![deny(clippy::all, clippy::pedantic)]`. Unsafe is banned across the workspace.
- **Error handling**: three-layer model — internal `AppError` (`thiserror`, `#[non_exhaustive]`, `&'static str` codes for things like `policy`/`code`/`dep`), public `PublicError` (only type ever serialized), and `ErrorClassification` for retryability/alerting. `http::into_response_parts` is the single source of truth used by both axum and actix adapters so responses are byte-identical. Panics are caught at the boundary via `panic::catch_panic_to_safe_response`.
- **Identity-agnostic core**: `security_core::IdentitySource` is the load-bearing trait (`AuthenticatedIdentity { actor_id, tenant_id, roles, attributes, authenticated_at }`); `secure_authz` depends only on this trait so any identity provider plugs in. Marked `#[non_exhaustive]` for forward compatibility.
- **Default-deny everywhere**: authorization denies by default, unknown JSON fields rejected (`SecureJson` + `StrictDeserialize`), secrets redacted in `Debug`/`Display`/`Serialize` (`SecretString`/`secrecy`), CORS denies cross-origin by default.
- **DTO-only deserialization**: handlers receive `SecureJson<Dto>` not domain models; `SecureValidate` trait splits `validate_syntax` from `validate_semantics`.
- **Schema-driven redaction**: every telemetry field is tagged via `DataClassification`; only `Public` fields leave the process unredacted. `security_events` HMAC-seals events.
- **Feature-gated optional integrations**: heavy/optional deps (Vault, AWS KMS, Azure KV, Argon2, OIDC, Redis, biometric, mobile-storage, FIPS, html-sanitize) live behind crate features, all off by default. Framework adapters (`axum`, `actix-web`) are also features (axum is default for `secure_authz`).
- **Logging**: `tracing` everywhere; reference binary uses `tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env())`.
- **Async style**: `async fn` with tokio; per-crate tokio feature trimming (`["sync", "time", "rt"]`) to keep dependency surfaces minimal in libraries; binaries use `features = ["full"]`.
- **Testing layers**: unit, `proptest` property tests (prop_), CVE-regression tests (cve_), timing tests (timing_, `--ignored` to keep them off CI), `e2e_*` integration tests, `cargo-fuzz` targets per-crate, miri for memory safety.
- **Pre-flight validation**: services validate `SecurityConfig` at startup and `std::process::exit(1)` on misconfiguration (fail-fast).

## Constraints

- **License**: MIT for every workspace crate. `deny.toml` allow-list is `MIT, Apache-2.0, BSD-2/3-Clause, ISC, Zlib, Unicode-3.0, Unicode-DFS-2016, CC0-1.0`. Copyleft denied except two named exceptions: `r-efi` (LGPL-2.1-or-later, UEFI-only transitive) and `smartstring` (MPL-2.0, transitive via rhai).
- **Supply-chain policy**: every dep must come from `crates.io`; `unknown-registry = "deny"`, `unknown-git = "deny"`, no git deps. Every advisory ignore in `deny.toml` and `.cargo/audit.toml` requires a written justification and the two files must stay in sync. Current ignores: `RUSTSEC-2026-0002` (lru IterMut), `RUSTSEC-2023-0071` (rsa Marvin — verify-only path), `RUSTSEC-2026-0098/0099/0104` (rustls-webpki 0.101 via aws-smithy).
- **MSRV**: not declared. CI uses `dtolnay/rust-toolchain@stable`; nightly required only for `cargo +nightly miri test` and `cargo +nightly fuzz`.
- **Platforms**: CI tests `ubuntu-latest`, `macos-latest`, `windows-latest`. `mobile-storage` and `mobile-platform` features target mobile (MASVS) but no iOS/Android-specific build is in CI — no file confirms native-mobile CI today.
- **Safety**: `#![forbid(unsafe_code)]` is applied at the crate root for the libraries inspected; new code must not introduce `unsafe`.
- **Lint gates**: clippy run with `-D warnings` over `--all-targets`; rustdoc built with `RUSTDOCFLAGS="-D warnings"` and `--all-features`. `cargo fmt --check` is enforced.
- **Feature-matrix gate**: `secure_boundary`, `secure_authz`, `secure_errors` must build/test cleanly under `""`, `axum`, `actix-web`, and `axum actix-web` feature combinations on every PR.
- **Compliance targets**: README cites OWASP Proactive Controls C1/C4/C5/C6/C7/C8/C9/C10 and OWASP MASVS-AUTH/STORAGE/NETWORK; THREAT_MODEL.md references NIST 800-53 (AC, AU, IA, SC, SI), IEC 62443, SOC 2 Type II — future changes should preserve those mappings.
- **Reference vs production**: `secure_reference_service` ships a `DevAuthLayer` explicitly marked NOT-for-production; production deployments must replace it with a real `IdentitySource`.
- **Not inspected**: no `pyproject.toml`, `package.json`, `go.mod`, or `Makefile` exists at the repo root — there is no Python/Node/Go build surface to honor.

## Executive Summary

The repository is well-positioned to go public: 13 crates with `#![forbid(unsafe_code)]`, a working CI matrix on three OS, in-tree `cargo-fuzz` harnesses across 8 of 13 crates (18 targets), a curated `deny.toml` with justified RUSTSEC ignores, `cargo-vet` 0.10 already wired with ~990 exemptions, and DAST workflows already in place. The remaining work is governance scaffolding plus 2026-current supply-chain hardening, not novel engineering.

Research resolves the five blocking questions decisively. Trusted Publishing on crates.io is **GA** for GitHub Actions (RFC 3691, July 2025; per-crate enforce-mode added January 2026), with the one caveat that *first publish of a new crate still requires a long-lived token* before TP can take over. CodeQL Rust is **GA** (CodeQL 2.23.3, 2025-10-23), making it the natural primary SAST with Semgrep (also Rust-GA) as additive coverage. `actions/attest-build-provenance@v2` alone meets **SLSA Build Level 2**; Level 3 requires the build steps to live in a *reusable workflow* (or `slsa-framework/slsa-github-generator`). The dual-license `MIT OR Apache-2.0` default is unchanged in 2026 — every crate currently declares only `MIT`, so the manifests need a sweep. All four `cargo-vet` publisher feeds (Mozilla, Google, Bytecode Alliance, Embark Studios) are live in `mozilla/cargo-vet/registry.toml`.

Two findings reshape expectations. OpenSSF Scorecard's Code-Review check uses tiered point deductions, not proportional scoring: a solo maintainer who self-merges scores **0/10** on Code-Review regardless of CODEOWNERS — realistic overall ceiling for a solo Rust security repo is **6–7/10**, not the 8+ implied by earlier estimates, and a target score should not be advertised. Cross-platform reproducible builds are **not feasible in 2026** for this workspace because `aws-lc-rs`/`ring` pull C/CMake toolchains and the Rust toolchain itself is not yet bit-reproducible (rust-lang/rust#34902; cargo PR #16691 still in flight); single-platform single-runner sha256 comparison is the achievable bar.

The credible launch posture is **SLSA L2 + Trusted Publishing + cosign keyless + CodeQL + OSV-Scanner + dependency-review + Scorecard + harden-runner (audit→block) + cargo-vet `[imports]`**, with SLSA L3 reusable-workflow refactor, `secure_authz` fuzz coverage, OSS-Fuzz application, and OpenSSF Best Practices Badge as documented post-1.0 work. OSS-Fuzz acceptance is discretionary on a "criticality score" (large user base or essential dependents) — a brand-new repo with zero downstream users is unlikely to clear the bar at announcement, so deferring it is a research-supported decision, not a punt.

## Topic Decomposition

The user's prompt distilled five highest-leverage research questions; the raw findings expanded these to twelve, several of which were tightened or merged during deepening. The final decomposition:

- **Q1 — crates.io Trusted Publishing status (April 2026):** GA, beta, or proposed? Drives M5 release-workflow and whether any long-lived `CRATES_IO_TOKEN` posture is needed.
- **Q2 — SLSA tier reachable with `actions/attest-build-provenance@v2`:** Level 2 (standalone) vs Level 3 (reusable workflow / `slsa-github-generator`). Drives the README "SLSA Level X" claim and M3 architecture.
- **Q3 — OSS-Fuzz Rust onboarding:** acceptance criteria, expected turnaround, idiomatic harness shape for parsing crates (HTML sanitizer, JWT/OIDC, regex sinks). Drives M4 scope.
- **Q4 — CodeQL Rust GA vs Semgrep + OSV-Scanner:** primary SAST tool selection.
- **Q5 — License default for Rust security crates in 2026:** `MIT OR Apache-2.0` vs Apache-only / source-available alternatives. Drives M1 LICENSE files and every manifest.
- **Q6 — `cargo-vet` `[imports]` availability:** confirm Mozilla, Google, Bytecode Alliance, Embark Studios feeds and canonical URLs.
- **Q7 — `cosign verify` UX:** required flags for keyless verification (`--certificate-identity`, `--certificate-oidc-issuer`); bundle-format simplifications. Drives README "how to verify."
- **Q8 — `step-security/harden-runner` posture:** OS support and audit→block burn-in duration.
- **Q9 — `actions/dependency-review-action` Cargo support:** GA status and policy-file format.
- **Q10 — OpenSSF Scorecard realistic ceiling for a solo-maintainer Rust repo:** which checks are structurally low; credible stretch score.
- **Q11 — MSRV defensible floor for security libraries in 2026:** numeric anchor and policy posture.
- **Q12 — GHSA + RUSTSEC dual reporting:** unified intake or still two-step?

Three repo-grounded sub-questions surfaced during synthesis: (a) Trusted Publishing first-publish bootstrap, (b) reproducible-build feasibility against `aws-lc-rs` / `ring`, and (c) `cargo-semver-checks` behaviour on feature-gated APIs given the workspace's feature matrix.

## Key Findings

**Trusted Publishing on crates.io is GA for GitHub Actions (high confidence).** RFC 3691 shipped to production in July 2025; the January 2026 development update added per-crate **enforcement mode** (when on, traditional API tokens are refused for that crate) and added **GitLab.com CI/CD** as a public-beta provider (self-hosted GitLab not supported). Two GitHub triggers — `pull_request_target` and `workflow_run` — are explicitly refused as TP sources because they run on the target repository's permissions. **First publish of a *new* crate still requires a long-lived token**; TP can only authorise *subsequent* publishes once the crate exists on crates.io. Implication for a 13-crate workspace: a one-shot bootstrap publish round, then TP registration per crate, then enforce-mode toggle, then token deletion.

**`actions/attest-build-provenance@v2` standalone is SLSA Build Level 2; Level 3 requires a reusable workflow (high confidence — resolved contradiction).** Earlier vendor-blog framing positioned the action as L3-out-of-the-box, but GitHub's own documentation page "Using artifact attestations and reusable workflows to achieve SLSA v1 Build Level 3" makes the requirement explicit: the build steps must run inside a reusable workflow so signing material is unreachable from user-defined steps. The independent Ian Lewis explainer reaches the same conclusion. The action emits SLSA v1.0 build-provenance predicates wrapped in in-toto, signed by Sigstore (Fulcio + Rekor for public repos; GitHub's private Sigstore instance for private repos). Required permissions: `id-token: write` and `attestations: write`. The alternative L3 path is `slsa-framework/slsa-github-generator`'s reusable workflows.

**CodeQL Rust is GA (high confidence — resolved contradiction).** Public preview shipped in CodeQL 2.22.1 (2025-07-02); GA shipped in **CodeQL 2.23.3 (2025-10-23)**. The release added `rust/insecure-cookie` as a starter security query, and 2.23.7/2.23.8 (2025-12-18) added more Rust + Go security queries — rule coverage is still expanding post-GA. Some 2026 third-party comparison write-ups (Konvu, AppSec Santa, DEV.to) still describe CodeQL Rust as "preview"; these are out of date relative to GitHub's own changelog. CodeQL Rust uploads to the GitHub Security tab natively, which Semgrep does not (without commercial integrations).

**Semgrep Rust is GA.** Promoted from 2023 beta. The LinkedIn 2026 SAST pipeline reportedly runs both CodeQL and Semgrep in parallel — additive, not redundant: CodeQL gives semantic dataflow, Semgrep gives fast pattern-based OWASP coverage.

**OSV-Scanner v2.3.5 (March 2026) covers Cargo lockfiles natively (high confidence).** Aggregates OSV.dev, which mirrors GHSA + RustSec + others. SARIF output for Security-tab upload. Genuinely additive on top of `cargo audit` because GHSA can surface advisories ahead of RustSec landing.

**`actions/dependency-review-action` v4.9.0 (2026-03-03) supports Cargo via GHSA (high confidence).** License-allowlist + `fail-on-severity` are first-class config. PR-event only; does not replace `cargo audit` on `main`/cron.

**`step-security/harden-runner` is now cross-platform (high confidence).** Linux, macOS, and Windows runners are supported with the same syntax. The repo's existing 3-OS CI matrix can adopt harden-runner uniformly. Audit-mode burn-in has no fixed upstream duration; the documented protocol is "audit, observe across multiple runs, transition via the Recommendations tab." Practical floor for this repo: ~5–10 distinct runs across the matrix (~1 week) before flipping to `block`. Egress allowlist must include `crates.io`, `static.crates.io`, `index.crates.io`, `github.com`, `objects.githubusercontent.com`, plus any `Swatinem/rust-cache` / `actions/cache` endpoints in use.

**`MIT OR Apache-2.0` remains the unambiguous default for Rust crates (high confidence).** Confirmed by the Rust API Guidelines and Google's third-party Rust open-source guidance; the Apache patent grant plus MIT's GPL-2.0/LGPL-2.1 compatibility (Apache-2.0 alone is GPL-2-incompatible) are the rationale. No 2025–2026 search signal of community drift toward Apache-only-with-patent-grant or commercial-protection (BSL/SSPL) for general crates. **Repo gap:** all 13 crates currently declare `license = "MIT"` and there are no LICENSE files at the repo root.

**`cargo-vet` 0.10.2 is the current line; all four canonical `[imports]` feeds are live (high confidence).** The repo's `version = "0.10"` declaration in `supply-chain/config.toml` is correct. Mozilla's `cargo-vet/registry.toml` lists nine publisher feeds; the four named in the prompt and several others have stable raw-GitHub URLs (see API & SDK Documentation). The repo currently has no `[imports]` block. Existing `supply-chain/config.toml` carries ~248 exemptions per the readiness analysis (and ~990 exemption lines per iter-3's reading) — concrete burn-down work for M4.

**Cosign keyless verification UX is unchanged but bundle-format simplifies it (high confidence).** `cosign verify-blob` still requires `--certificate-identity` (or `--certificate-identity-regexp`) and `--certificate-oidc-issuer` (`https://token.actions.githubusercontent.com` for GitHub-built artifacts). Cosign **v2.4.0** introduced bundle-format `verify-blob-attestation` for GitHub Artifact Attestations / npm provenance / Homebrew provenance — single-file flow, offline verification works, signed timestamps + attestation in one bundle. Alternative for downstream consumers: `gh attestation verify` consumes the same Sigstore bundle without a Cosign install. Implication for README: the verify command must be documented verbatim including the exact OIDC issuer and identity regex — neither is derivable from the artifact alone.

**`MIT OR Apache-2.0` is the licensing default; default-deny patterns dominate the existing repo posture.** The repo's existing `deny.toml` allowlist already accepts `Apache-2.0`, so flipping every manifest to dual-license requires no policy change — only manifest edits and two LICENSE files at repo root.

**OpenSSF Scorecard's Code-Review check is tiered, not proportional (high confidence).** −7 points for one unreviewed human change, −3 more for multiple, −3 for unreviewed bot changes. **A solo maintainer who self-merges scores 0/10 on Code-Review regardless of CODEOWNERS** — only an approving review by a different account counts. **Contributors** check requires "≥3 different companies in last 30 commits, each with ≥5 commits" for full marks. Realistic ceiling for a solo Rust security repo executing every other check well: **6–7 / 10 overall**. Earlier "8/10 stretch" estimates were too optimistic. Recommendation supported by the findings: do not advertise a target score in README until a co-maintainer joins.

**OSS-Fuzz Rust onboarding is mature in shape but discretionary in acceptance (medium confidence).** The official Rust integration guide is current: harnesses are authored with `cargo-fuzz`; integration adds `projects/<name>/{project.yaml, Dockerfile, build.sh}` to the `google/oss-fuzz` repo; the OSS-Fuzz builder image ships nightly Rust + `cargo fuzz` pre-installed. Acceptance is gated by a "criticality score" — large user base or essential dependents. A brand-new repo with zero downstream dependents on crates.io is unfavourable at announcement time. No 2026 turnaround SLA was surfaced; the path forward is in-tree harnesses now (already done for 8/13 crates), OSS-Fuzz application post-1.0 once external adoption exists. The `rust-base64` onboarding PR (`google/oss-fuzz#10693`) is a working reference for parser-style crates.

**MSRV: no 2026 community-blessed numeric default; project-specific decision (medium confidence).** The Rust API Guidelines (rust-lang/api-guidelines #231) document trade-offs, recommend declaring MSRV explicitly, testing it in CI with pinned lockfiles, and treating MSRV bumps as **minor-version** for `≥1.0` (patch for `<1.0`). RFC 3537 (MSRV-aware resolver) is now in Cargo and reduces the cost of a conservative floor. Common policies in the wild: "last two stable Rust versions" (rolling), "stable at most 3–6 months old," or "latest stable." `cargo-msrv` 0.19.3 (2026-03-25) is the de-facto tool: `cargo msrv find` discovers, `cargo msrv verify` gates CI. RustCrypto's policy of "MSRV bump is breaking, tested in CI" is a worked precedent for security libraries.

**Reproducible builds are not feasible cross-platform for this workspace in 2026 (high confidence).** The Rust toolchain does not produce bit-reproducible builds out of the box (rust-lang/rust#34902); cargo PR #16691 (March 2026) is in flight but not merged. `aws-lc-rs` (FIPS feature in `secure_data`) and `ring 0.17` (in `secure_identity`) pull C/CMake toolchains, making cross-OS Ubuntu/macOS/Windows reproducibility unachievable today. Achievable bar: **single-platform single-runner reproducibility** — pinned Ubuntu container, pinned toolchain, sha256 compared between two consecutive runs.

**RUSTSEC ↔ GHSA flow is one-way-mirrored, not unified (medium confidence).** `rustsec/advisory-db` remains the canonical Rust intake; GHSA imports RustSec advisories under CC-BY-4.0. For *reporting against your own crate* privately, the path is GitHub's private vulnerability reporting → GHSA → RustSec (the inverse direction). No 2026 announcement deprecating either side surfaced.

**`cargo-semver-checks` 0.47.0 (2026-03-08) is current (medium confidence).** v0.46 added cargo-feature-graph lints (`feature_newly_enables_feature` and friends). The `#[doc(hidden)]` false-positive class was fixed earlier via `public_api`/`public_api_eligible`. Tool MSRV is Rust 1.90. For this feature-matrix workspace, a single `--workspace` run misses feature-gated regressions — needs `--all-features` and `--no-default-features` legs (and likely the same `axum` / `actix-web` / `axum actix-web` / `""` matrix the existing CI runs).

**Repo grounding facts (high confidence — sourced from working tree):**
- All 13 crates: `edition = "2021"`, `version = "0.1.0"`, `license = "MIT"` (single, not dual). No `package.rust-version` declared. Workspace `resolver = "2"`.
- 8 of 13 crates have in-tree `cargo-fuzz` harnesses, **18 fuzz targets total**: `secure_boundary` (4: `fuzz_normalize`, `fuzz_validate`, `fuzz_deep_link`, `fuzz_webview_url`), `secure_data` (2), `secure_identity` (1), `secure_network` (3), `secure_output` (2), `secure_privacy` (2), `secure_resilience` (1), `security_events` (2). `libfuzzer-sys = "0.4"` is the harness library. `secure_authz` is the principal gap.
- Only **2 occurrences of `unsafe`** across the workspace — `cargo-geiger` will read very low; do not over-promise the badge meaning.
- `secure_data` uses `aws-lc-rs` (FIPS); `secure_identity` pulls `ring 0.17` — both bring C/CMake toolchains, which is what blocks cross-OS reproducibility.
- CI actions are pinned to mutable refs (`@v4`, `@v2`, `@stable`); no top-level `permissions:` block; no `--locked`; supply-chain tools installed via unpinned `cargo install`. SHA-pinning + tool-version-pinning + permission narrowing is real M2 work.
- `deny.toml` carries 5 well-justified RUSTSEC ignores: `RUSTSEC-2026-0002` (lru), `RUSTSEC-2023-0071` (rsa Marvin), `RUSTSEC-2026-0098/0099/0104` (rustls-webpki via aws-smithy). License allowlist already includes `Apache-2.0`.
- DAST workflows (`zap.yml`, `dastardly.yml`) already exist; the open question is gating policy, not authoring. `PortSwigger/dastardly-github-action@main` is the most-mutable pin and needs SHA replacement during M2.
- Governance scaffolding absent: no `LICENSE` / `LICENSE-MIT` / `LICENSE-APACHE`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, `CODEOWNERS`, `GOVERNANCE.md`, issue/PR templates, or `dependabot.yml`.

## Library & Tool Evaluations

**`actions/attest-build-provenance@v2`** — Native Sigstore Fulcio + Rekor signing; integrates with GitHub's built-in attestations API; consumable via `gh attestation verify` or `cosign verify-blob`. Standalone tops out at SLSA Build L2; the documented L3 path is to wrap build steps in a reusable workflow. SHA pin required for hardened CI. Requires `id-token: write` + `attestations: write` permissions. **Use** for L2 immediately; refactor to reusable workflow before claiming L3 anywhere in README.

**`slsa-framework/slsa-github-generator`** — Language-agnostic reusable-workflow framework, alternative path to SLSA L3. Less Rust-specific exemplar material than the attest-build-provenance + reusable-workflow path; adds a second maintained dependency tier. **Backup option** if the in-house reusable-workflow refactor proves operationally heavy.

**`actions/dependency-review-action` v4.9.0 (2026-03-03)** — Cargo via GHSA mirror; license-allow/deny + severity gates first-class; PR-time block. Pull-request event only — does not replace `cargo audit` on `main`/cron. **Use** as a PR gate alongside, not instead of, `cargo audit`.

**`step-security/harden-runner` (latest 2.19.x)** — Cross-platform (Linux/macOS/Windows) — covers the existing 3-OS matrix uniformly. Egress audit→block transition is the documented pattern; ~1 week burn-in for this Rust-heavy multi-OS matrix is the practical floor. **Use** in `audit` mode at launch, flip to `block` after one full week of clean baselines.

**`google/osv-scanner` v2.3.5 (March 2026)** — Aggregates OSV.dev (GHSA + RustSec + others); SARIF output; Cargo lockfile native. Overlaps with `cargo audit` and `dependency-review-action`. **Use** with intentional de-duplication (e.g., `cargo audit` on cron, `dependency-review` on PR, OSV-Scanner weekly with SARIF upload).

**CodeQL — Rust GA in 2.23.3 (2025-10-23)** — Native GitHub Security tab integration; high recall historically; rule library is starter-level for security-specific Rust patterns. **Use** as the primary SAST.

**Semgrep — Rust GA** — Complements CodeQL with `p/rust` + `p/owasp-top-10` rulesets; faster local feedback; separate alert surface. **Use** alongside CodeQL.

**`cargo-vet` 0.10.2** — Matches the repo's existing `version = "0.10"` declaration; canonical imports live for all four named orgs (Mozilla, Google, Bytecode Alliance, Embark Studios) plus five more in `registry.toml`. The repo currently has ~248–990 exemption lines (range across iter readings) — burn-down is real labor with a documented target (e.g., "≤50 by 1.0"). **Already in use; add `[imports]`.**

**`cargo-msrv` 0.19.3 (2026-03-25)** — `cargo msrv verify` exits non-zero on failure, drop-in CI gate; reads `package.rust-version`. Requires an MSRV chosen first via `cargo msrv find`. **Use** in dedicated MSRV CI job.

**`cargo-mutants` v27.0.0 (2026-03-07)** — Long runtimes; needs a curated `mutants.toml` to be CI-viable. Security-invariant tests benefit disproportionately from mutation testing. **Use** scoped to security-invariant crates (`secure_boundary`, `secure_authz`, `secure_identity`, `security_events`); off the PR critical path.

**`cargo-geiger` 0.13.0 (2025-08-31)** — Simple unsafe-LOC counter; known to undercount expressions inside `unsafe fn` bodies; treat the number as a directional signal. With only 2 `unsafe` occurrences in this workspace, the badge will read very low. **Use** for periodic reporting; do not gate CI on the count.

**`cargo-semver-checks` 0.47.0 (2026-03-08)** — Tool MSRV Rust 1.90; v0.46+ added cargo-feature-graph lints; `#[doc(hidden)]` false-positive class fixed via `public_api` / `public_api_eligible`. For this feature-matrix workspace, single-`--workspace` invocation misses feature-gated regressions. **Use** post-1.0 only as a release gate, not PR gate; matrix over `--all-features` + `--no-default-features` (and ideally the same `axum`/`actix-web` permutations CI already runs).

**`actions/dependabot` (cargo + github-actions ecosystems)** — Native; required to keep SHA-pinned actions current; bumps trigger churn for a solo maintainer. **Use** with grouped updates and weekly cadence to limit churn.

**`taiki-e/install-action`** — SHA-pinnable; supports explicit `--version`; covers `cargo-audit`, `cargo-deny`, `cargo-vet`, `cargo-llvm-cov`, `cargo-mutants`. Itself another transitive trust point — must be SHA-pinned. **Use** to fix the unpinned `cargo install ...` pattern in current `supply-chain` job.

**`release-plz` vs `cargo-release`** — `release-plz` is designed for multi-crate workspaces, generates auto-PRs, and has first-class crates.io Trusted Publishing support; `cargo-release` is more imperative and scriptable. **Prefer `release-plz`** for this 13-crate workspace; first-publish bootstrap (long-lived token, one-shot) still required regardless of tool.

**`cosign` v2.4.0+** — `verify-blob-attestation` with bundle format; offline verification works; consumer-facing flags (`--certificate-identity`/`--certificate-identity-regexp`, `--certificate-oidc-issuer`) still required and must be documented verbatim in README. **Use**.

**OSS-Fuzz Rust toolchain** — Builder image ships nightly Rust + `cargo fuzz` pre-installed; harnesses live at `crates/<crate>/fuzz/fuzz_targets/*.rs` (already present for 8/13 crates). Acceptance gated by criticality score; new repo with no downstream dependents is unfavourable. **Use post-1.0**, not at launch; the in-tree harnesses are independently valuable via local + CI runs without OSS-Fuzz acceptance.

**Reproducible-build tooling (`diffoscope` / sha256 compare)** — Cross-OS infeasible due to `aws-lc-rs`/`ring` and Rust-toolchain-level reproducibility gaps. **Use** scoped to one canonical pinned-Ubuntu platform; defer multi-platform until cargo PR #16691 lands.

## Architecture Options

**Option A — Full mission-critical posture at launch.** SLSA L3 via reusable workflow + `attest-build-provenance@v2` *or* `slsa-github-generator`; Trusted Publishing on every crate (after manual first-publish bootstrap); cosign keyless on every release artifact + SBOM; CodeQL + Semgrep + OSV-Scanner + dependency-review + harden-runner (block) + Scorecard all running; cargo-vet `[imports]` from all four orgs; in-tree `cargo-fuzz` nightly across all 13 crates including `secure_authz`; OSS-Fuzz application opened post-launch (acceptance is discretionary regardless). **Trade-offs:** strongest "mission-critical" claim; all README claims survive scrutiny. Reusable-workflow refactor is the longest single task; four scanner alert streams demand triage discipline; overruns the 5–6 day P0+P1 budget unless slips are accepted on L3 ceremony or `secure_authz` fuzz coverage. **Best fit:** maintainer is willing to delay public toggle until everything lands and accepts ongoing alert-triage labour.

**Option B — Hardened MVP at launch, L3 + OSS-Fuzz post-launch (research-supported recommendation for the stated 5–6 day budget).** *Day one:* SLSA **L2** via `attest-build-provenance@v2`; Trusted Publishing on all 13 crates after one-shot manual bootstrap publish; cosign keyless; CodeQL + OSV-Scanner + `dependency-review-action` + Scorecard + `harden-runner` (audit); `cargo-vet` imports from Mozilla + Embark only at launch (smallest delta); `cargo-msrv` verify gate using a measured floor; in-tree `cargo-fuzz` nightly using existing 18 harnesses; single-platform Ubuntu sha256-compare reproducibility. *Week 2:* add Semgrep `p/rust` + `p/owasp-top-10`; add Google + Bytecode Alliance vet imports; flip `harden-runner` audit→block. *1.0 cut:* SLSA L3 reusable-workflow refactor; `cargo-semver-checks` release-gate; OSS-Fuzz application; `secure_authz` fuzz-harness fill-in; OpenSSF Best Practices Badge. **Trade-offs:** realistic for one solo maintainer in budget; defensible launch claim ("SLSA L2 with documented L3 roadmap, signed releases, Trusted Publishing, 18 in-tree fuzz targets"). "SLSA L3" cannot appear in launch README; Code-Review Scorecard sits at 0/10 until a co-maintainer joins — accept and don't advertise a target score; an explicit "current state" section in README that survives a year of drift is needed.

**Option C — Conservative launch (no Trusted Publishing, no L3, no fuzz CI, no signing).** Long-lived `CRATES_IO_TOKEN` in a GitHub Environment with required-reviewer gate; SLSA L2 with `attest-build-provenance`; Scorecard + dependency-review + CodeQL + `harden-runner` (audit). Defer Trusted Publishing + cosign + cargo-vet imports + fuzz CI to a "1.1" release. **Trade-offs:** smallest blast radius; minimal moving parts. Undercuts the "mission-critical" framing — long-lived publish tokens are exactly what TP exists to eliminate; no signed releases on day one is hard to justify in the README of a self-described mission-critical OSS project. **Research-supported verdict: dominated by Option B given TP is GA; rejected unless an external constraint forces conservatism.**

## API & SDK Documentation

**crates.io Trusted Publishing**
- RFC 3691 specifies the design; configuration UI lives in each crate's `Settings → Trusted Publishing` panel.
- Required GitHub Actions permissions on the publishing job: `id-token: write`. The OIDC token is exchanged at crates.io for a short-lived publish token.
- `pull_request_target` and `workflow_run` triggers are refused as TP sources.
- First publish of a new crate cannot use TP; bootstrap requires a long-lived `CRATES_IO_TOKEN`. Once the crate exists, register the TP relationship, then enable enforce-mode (rejects API tokens) and revoke the bootstrap token.
- GitLab.com is in public beta; self-hosted GitLab is not supported.

**`actions/attest-build-provenance@v2`**
- Inputs: `subject-path` (built artifact path; supports globs and multiple subjects). Required permissions: `id-token: write`, `attestations: write`.
- Output: in-toto SLSA v1.0 build-provenance predicate signed via Sigstore (Fulcio cert + Rekor entry on public repos; GitHub private Sigstore for private repos).
- Verification (consumer side): `gh attestation verify <artifact> --owner <org>` or `cosign verify-blob --bundle <bundle> --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-identity-regexp <workflow-path-regex>`.
- For SLSA L3: place build steps inside a reusable workflow file (e.g., `.github/workflows/_build.yml` invoked via `uses: ./.github/workflows/_build.yml`). The reusable workflow is the unit that calls `attest-build-provenance`; the caller workflow does not.

**`cargo-vet` `[imports]` — canonical URLs from `mozilla/cargo-vet/registry.toml` (April 2026)**
- Mozilla — `https://raw.githubusercontent.com/mozilla/supply-chain/main/audits.toml`
- Google — `https://raw.githubusercontent.com/google/supply-chain/main/audits.toml`
- Bytecode Alliance — `https://raw.githubusercontent.com/bytecodealliance/wasmtime/main/supply-chain/audits.toml`
- Embark Studios — `https://raw.githubusercontent.com/EmbarkStudios/rust-ecosystem/main/audits.toml`
- Fermyon — `https://raw.githubusercontent.com/fermyon/spin/main/supply-chain/audits.toml`
- ISRG — `https://raw.githubusercontent.com/divviup/libprio-rs/main/supply-chain/audits.toml`
- Actix — `https://raw.githubusercontent.com/actix/supply-chain/main/audits.toml`
- Ariel OS — `https://raw.githubusercontent.com/ariel-os/ariel-os/main/supply-chain/audits.toml`
- Zcash — `https://raw.githubusercontent.com/zcash/rust-ecosystem/main/supply-chain/audits.toml`

Trust must be added explicitly per organisation in `supply-chain/config.toml`; `cargo vet` fetches each URL and writes results to `imports.lock`.

**OSS-Fuzz Rust integration**
- Project layout (in this repo, already present): `crates/<crate>/fuzz/Cargo.toml`, `crates/<crate>/fuzz/fuzz_targets/<name>.rs` using `libfuzzer-sys`.
- OSS-Fuzz onboarding adds `projects/<name>/{project.yaml, Dockerfile, build.sh}` to `google/oss-fuzz`; `build.sh` invokes `cargo fuzz build`.
- `project.yaml` requires a primary contact email with a verifiable affiliation.
- Reference precedent for parser-style crates: `google/oss-fuzz#10693` (`rust-base64` onboarding).

**Cosign verify (consumer-facing)**
- `cosign verify-blob --bundle <bundle.json> --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-identity-regexp <workflow-identity-regexp> <artifact>`
- The OIDC issuer and identity regex are not derivable from the artifact alone — must be documented in README.
- Bundle format added in cosign v2.4.0; signed timestamps + attestation in one file; offline verification works.

**OpenSSF Scorecard — relevant check mechanics**
- `Code-Review`: tiered deductions (−7 / −3 / −3) — solo self-merging hits 0/10 regardless of CODEOWNERS.
- `Maintained` / `Contributors`: `Contributors` requires ≥3 different companies in last 30 commits, each with ≥5 commits, for full score.
- 18+ checks total, scored 0–10 each.

## Design Recommendations

The recommendations below reflect what the raw findings directly support; they are inputs to `/slo-plan`, not a milestone breakdown.

1. **Adopt `MIT OR Apache-2.0` dual-licensing across all 13 crates.** *(confidence: high)* Add `LICENSE-MIT` and `LICENSE-APACHE` at repo root; flip every `Cargo.toml` `license` field; the existing `deny.toml` allowlist already accepts both. Rationale is the explicit Apache-2.0 patent grant + MIT's GPL-2/LGPL-2 compatibility.

2. **Mandate Trusted Publishing for every crate, with a one-shot bootstrap-token publish for first-version of each new crate.** *(confidence: high)* After bootstrap: register TP relationship per crate; enable per-crate enforce-mode; revoke the bootstrap `CRATES_IO_TOKEN`. Use `release-plz` for the steady-state multi-crate workflow; reject Option C's long-lived-token posture.

3. **Claim "SLSA Build Level 2" at launch via `actions/attest-build-provenance@v2`; treat L3 (reusable workflow refactor) as a documented post-launch deliverable.** *(confidence: high)* Do not put "SLSA L3" in the launch README without the reusable-workflow refactor in place.

4. **Make CodeQL the primary SAST; add Semgrep `p/rust` + `p/owasp-top-10` as additive coverage in week 2.** *(confidence: high)* CodeQL Rust is GA (2.23.3, Oct 2025) with native Security-tab integration. Run OSV-Scanner separately on a weekly cadence to capture GHSA-only advisories.

5. **Cover all CI surfaces with `step-security/harden-runner` in audit mode; flip to block after ~1 week of clean baselines across the existing 3-OS matrix.** *(confidence: high)* Pre-allowlist `crates.io`, `static.crates.io`, `index.crates.io`, `github.com`, `objects.githubusercontent.com`, plus cache endpoints.

6. **Wire `cargo-vet` `[imports]` from at least Mozilla + Embark Studios at launch; add Google + Bytecode Alliance in week 2.** *(confidence: high)* Document a written burn-down target for the existing exemptions (e.g., "≤50 by 1.0"). All canonical URLs are in `mozilla/cargo-vet/registry.toml`.

7. **Set MSRV per-crate via `cargo msrv find`, declare in `package.rust-version`, gate CI with `cargo msrv verify`, document an MSRV-bump-is-minor-version policy.** *(confidence: medium)* No 2026 community-blessed numeric default exists; the choice is project-specific based on which Rust features the workspace actually uses. RustCrypto's "MSRV is breaking" policy is a reasonable precedent for security libraries; RFC 3537's MSRV-aware resolver lowers the cost of a conservative floor.

8. **Add `actions/dependency-review-action` v4.9.0 as a PR gate alongside the existing `cargo audit` job — not in place of it.** *(confidence: high)* `dependency-review-action` is PR-event only; `cargo audit` covers `main`/cron.

9. **Sign every release artifact with cosign keyless; document the `verify-blob` invocation verbatim in README, including the exact OIDC issuer and identity regex.** *(confidence: high)* Use cosign v2.4.0+ bundle format. Note `gh attestation verify` as a no-Cosign-install alternative for downstream consumers.

10. **Defer OSS-Fuzz onboarding to post-1.0; rely on the existing 18 in-tree `cargo-fuzz` harnesses with a CI nightly schedule.** *(confidence: medium)* Acceptance is discretionary on a criticality score; a brand-new repo without downstream dependents is unlikely to clear the bar at announcement. Fill the `secure_authz` harness gap as separate work.

11. **Implement reproducibility verification on a single pinned-Ubuntu runner only — sha256-compare two consecutive runs of one crate.** *(confidence: high)* Cross-OS reproducibility is unachievable with `aws-lc-rs`/`ring` in the dependency tree and the open Rust-toolchain reproducibility gap. Revisit when cargo PR #16691 stabilises.

12. **Adopt OpenSSF Scorecard but do not advertise a target score in README until a co-maintainer joins.** *(confidence: high)* Code-Review check is structurally 0/10 for solo self-merging; realistic ceiling for a solo Rust security repo is 6–7/10.

13. **Use `cargo-semver-checks` as a release-gate (not PR-gate) post-1.0, matrixed over feature combinations.** *(confidence: medium)* Single `--workspace` invocation misses feature-gated regressions; mirror the existing CI feature matrix (`""`, `axum`, `actix-web`, `axum actix-web`).

14. **SHA-pin every GitHub Action and use `taiki-e/install-action` with explicit `--version` for cargo tooling.** *(confidence: high)* Replaces the current `@v4` / `@stable` / `@v2` mutable refs and the unpinned `cargo install cargo-audit cargo-deny cargo-vet`. Add Dependabot for the `github-actions` and `cargo` ecosystems with grouped weekly updates.

15. **Add a top-level `permissions:` block scoped to least privilege on every workflow; widen only for jobs that need `id-token: write` / `attestations: write`.** *(confidence: high)* The current CI has no explicit `permissions:` block, defaulting to broad `GITHUB_TOKEN` scopes.

16. **Use `cargo-mutants` v27.0.0 scoped to `secure_boundary`, `secure_authz`, `secure_identity`, `security_events` only; off the PR critical path.** *(confidence: medium)* Long runtimes; mutation testing is high-value for security invariants but needs a curated `mutants.toml`.

17. **Use `cargo-geiger` 0.13.0 for periodic unsafe-LOC reporting; do not gate CI on the count or use the badge as a marketing signal.** *(confidence: medium)* Only 2 `unsafe` occurrences exist in the workspace today and the tool is known to undercount expressions inside `unsafe fn` bodies.

18. **Treat the existing DAST workflows (`zap.yml`, `dastardly.yml`) as already-present and define an explicit gating policy as part of the launch readiness work, not new authoring.** *(confidence: high)* Re-pin `PortSwigger/dastardly-github-action@main` to a SHA during action-pinning work.

## Risks & Open Questions

Ordered by leverage on the launch decision.

1. **Concrete MSRV number for this workspace.** No community-blessed 2026 default. Resolution: run `cargo msrv find` once across the workspace and pick by toolchain features actually used (e.g., `let-else`, `async fn` in traits, `LazyLock`). Discovery work, not research.

2. **`secure_authz` fuzz-harness entry-point shape.** The principal in-tree fuzz coverage gap. Repo work, not external research; needs brief code review of `policy.rs` + `enforce.rs`.

3. **First-publish bootstrap mechanics at workspace scale.** TP cannot publish a *new* crate; the workspace has 13 first-publishes to coordinate. Resolution: read 1–2 recent multi-crate workspaces' release-plz migration PRs for the operational pattern.

4. **OpenSSF Scorecard peer benchmark for solo Rust security repos.** No 2026 numeric benchmark surfaced for "realistic stretch." Resolution: query `scorecard.dev` for ~3 comparable solo Rust security crates (e.g., `argon2`, `password-hash`) and read their score breakdowns to calibrate the README's no-target-score posture.

5. **Where to gate the existing DAST workflows.** Two reasonable placements: as a PR gate (in M2) or as a release gate (in M5) or both. Runbook decision, assigned to `/slo-plan`.

6. **`harden-runner` audit-mode burn-in length.** No fixed upstream duration. Repo-specific (depends on cache hits, registry mirrors, OS-specific runners). Only resolvable empirically; ~1 week of clean baselines on this 3-OS Rust matrix is the working estimate.

7. **Single-platform reproducible-build gate survival under `aws-lc-rs` rebuilds.** Empirical. Pilot two runs and `diffoscope` before committing the gate to a milestone.

8. **OSS-Fuzz onboarding turnaround in 2026.** No SLA surfaced. Resolution at the time of application: read the most recent 3–5 merged Rust onboarding PRs in `google/oss-fuzz` for time-from-PR-to-build-green.

9. **`cargo-semver-checks` behaviour on this workspace's feature-gated APIs.** v0.46+ added feature-graph lints, but explicit confirmation that `#[cfg(feature = "...")]`-gated public items in this workspace are checked correctly was not surfaced. Resolution: pilot `cargo semver-checks --all-features` and `--no-default-features` against one feature-rich crate (`secure_boundary` is a good candidate) and read the issue tracker for known feature-gating false positives.

10. **Specific Cosign release version to pin.** Sources confirm `v2.4.0` introduced bundle-format `verify-blob-attestation`; newer point releases likely shipped since but were not surfaced in research. Resolution: confirm against the `sigstore/cosign` releases page before pinning a version in CI.

11. **`actions/attest-build-provenance` patch version.** Action major `@v2` is the documented current line; specific patch SHA must be looked up at pin time.

12. **OSV-Scanner SARIF de-duplication tuning.** Three scanners (`cargo audit`, `dependency-review`, OSV-Scanner) overlap on advisory coverage. The recommendation is "intentionally de-duplicate" but the operational shape (which advisory IDs to suppress in which tool) is not in the findings.

13. **Whether the GitHub repo has any prior published crates under these names.** Affects whether some crates can use TP from the very first publish (unlikely; per readiness analysis, "no current published crates"). Worth a sanity check on `crates.io` for each of the 13 names before bootstrap.

14. **Resolved contradiction note (no longer open):** Two GitHub vendor-blog posts framed `attest-build-provenance` as L3-out-of-the-box; GitHub's own docs page and the Ian Lewis explainer make clear the action *alone* is L2 — this is the authoritative reading and the basis of recommendation #3.

15. **Resolved contradiction note (no longer open):** Some 2026 third-party comparison sites (Konvu, AppSec Santa, DEV.to) describe CodeQL Rust as "preview"; GitHub's own changelog (CodeQL 2.23.3, 2025-10-23) confirms GA — the authoritative source wins, and recommendation #4 reflects that.

## References

- [crates.io: development update — Rust Blog (2026-01-21)](https://blog.rust-lang.org/2026/01/21/crates-io-development-update/)
- [RFC 3691 — Trusted Publishing for crates.io](https://rust-lang.github.io/rfcs/3691-trusted-publishing-cratesio.html)
- [crates.io Trusted Publishing docs](https://crates.io/docs/trusted-publishing)
- [Publishing on crates.io — The Cargo Book](https://doc.rust-lang.org/cargo/reference/publishing.html)
- [Crates.io Implements Trusted Publishing Support — Socket.dev](https://socket.dev/blog/crates-launches-trusted-publishing)
- [Rust crates.io security update — Help Net Security (2026-01-21)](https://www.helpnetsecurity.com/2026/01/21/rust-crates-io-security-update/)
- [crates.io: Trusted Publishing — Simon Willison (2025-07-12)](https://simonwillison.net/2025/Jul/12/cratesio-trusted-publishing/)
- [crates.io Trusted Publishing from GitLab — GitLab issue #572760](https://gitlab.com/gitlab-org/gitlab/-/issues/572760)
- [Surfacing Security Advisories on crates.io — Alpha-Omega](https://alpha-omega.dev/blog/surfacing-security-advisories-on-crates-io-bringing-vulnerability-data-to-the-point-of-discovery/)
- [actions/attest-build-provenance — GitHub repo](https://github.com/actions/attest-build-provenance)
- [GitHub Marketplace — Attest Build Provenance](https://github.com/marketplace/actions/attest-build-provenance)
- [Using artifact attestations and reusable workflows to achieve SLSA v1 Build Level 3 — GitHub Docs](https://docs.github.com/actions/security-guides/using-artifact-attestations-and-reusable-workflows-to-achieve-slsa-v1-build-level-3)
- [Enhance build security and reach SLSA Level 3 with GitHub Artifact Attestations — GitHub Blog](https://github.blog/enterprise-software/devsecops/enhance-build-security-and-reach-slsa-level-3-with-github-artifact-attestations/)
- [Achieving SLSA 3 Compliance with GitHub Actions and Sigstore for Go modules — GitHub Blog](https://github.blog/security/supply-chain-security/slsa-3-compliance-with-github-actions/)
- [Strengthen your supply chain with code-to-cloud traceability and SLSA Build Level 3 security — GitHub Changelog (2026-01-20)](https://github.blog/changelog/2026-01-20-strengthen-your-supply-chain-with-code-to-cloud-traceability-and-slsa-build-level-3-security/)
- [slsa-framework/slsa-github-generator](https://github.com/slsa-framework/slsa-github-generator)
- [Understanding GitHub Artifact Attestations — Ian Lewis](https://www.ianlewis.org/en/understanding-github-artifact-attestations)
- [SLSA Level 3 in GitHub Actions: Build Provenance Without the Complexity — Peter Müller](https://pettll.net/blog/slsa-build-provenance-github-actions/)
- [Implementing SLSA Level 3 Build Provenance for Kubernetes Container Images — OneUptime](https://oneuptime.com/blog/post/2026-02-09-slsa-level3-build-provenance/view)
- [CodeQL scanning Rust and C/C++ without builds is now generally available — GitHub Changelog](https://github.blog/changelog/2025-10-14-codeql-scanning-rust-and-c-c-without-builds-is-now-generally-available/)
- [CodeQL 2.22.1 brings Rust support to public preview — GitHub Changelog](https://github.blog/changelog/2025-07-02-codeql-2-22-1-bring-rust-support-to-public-preview/)
- [CodeQL support for Rust now in public preview — GitHub Changelog](https://github.blog/changelog/2025-06-30-codeql-support-for-rust-now-in-public-preview/)
- [CodeQL 2.23.3 adds a new Rust query, Rust support, and easier C/C++ scanning — GitHub Changelog](https://github.blog/changelog/2025-10-23-codeql-2-23-3-adds-a-new-rust-query-rust-support-and-easier-c-c-scanning/)
- [CodeQL 2.23.7 and 2.23.8 add security queries for Go and Rust — GitHub Changelog](https://github.blog/changelog/2025-12-18-codeql-2-23-7-and-2-23-8-add-security-queries-for-go-and-rust/)
- [Supported languages and frameworks — CodeQL docs](https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/)
- [CodeQL library for Rust — CodeQL docs](https://codeql.github.com/docs/codeql-language-guides/codeql-library-for-rust/)
- [github/codeql GitHub repository](https://github.com/github/codeql)
- [Semgrep vs CodeQL (2026) — Konvu](https://konvu.com/compare/semgrep-vs-codeql)
- [Semgrep vs CodeQL: SAST Head-to-Head (2026) — AppSec Santa](https://appsecsanta.com/sast-tools/semgrep-vs-codeql)
- [GitHub CodeQL Review 2026 — AppSec Santa](https://appsecsanta.com/github-codeql)
- [Semgrep vs CodeQL: Lightweight Patterns vs Semantic Analysis for SAST (2026) — DEV.to](https://dev.to/rahulxsingh/semgrep-vs-codeql-lightweight-patterns-vs-semantic-analysis-for-sast-2026-412k)
- [Semgrep Rust GA support and Swift beta support](https://semgrep.dev/products/product-updates/rust-ga-support-and-swift-beta-support/)
- [Announcing Semgrep's Beta Support for Rust (2023)](https://semgrep.dev/blog/2023/announcing-semgrep-s-beta-support-for-rust/)
- [LinkedIn Redesigns SAST Pipeline — InfoQ (2026-02)](https://www.infoq.com/news/2026/02/linkedin-redesigns-sast-pipeline/)
- [Semgrep Alternatives — Aikido](https://www.aikido.dev/blog/semgrep-alternatives)
- [Announcing OSV-Scanner V2 — Google Security Blog (March 2025)](https://security.googleblog.com/2025/03/announcing-osv-scanner-v2-vulnerability.html)
- [google/osv-scanner](https://github.com/google/osv-scanner)
- [OSV-Scanner docs](https://google.github.io/osv-scanner/)
- [OSS-Fuzz documentation home](https://google.github.io/oss-fuzz/)
- [OSS-Fuzz: Integrating a Rust project](https://google.github.io/oss-fuzz/getting-started/new-project-guide/rust-lang/)
- [OSS-Fuzz Ideal Integration](https://google.github.io/oss-fuzz/advanced-topics/ideal-integration/)
- [google/oss-fuzz GitHub repository](https://github.com/google/oss-fuzz)
- [oss-fuzz#10693 — Onboard rust-base64 (reference PR)](https://github.com/google/oss-fuzz/pull/10693)
- [OSS-Fuzz — Trail of Bits Testing Handbook](https://appsec.guide/docs/fuzzing/oss-fuzz/)
- [cargo-fuzz — Trail of Bits Testing Handbook](https://appsec.guide/docs/fuzzing/rust/cargo-fuzz/)
- [Rust Fuzz Book — cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [rust-fuzz/cargo-fuzz GitHub repository](https://github.com/rust-fuzz/cargo-fuzz)
- [cargo-fuzz CHANGELOG](https://github.com/rust-fuzz/cargo-fuzz/blob/main/CHANGELOG.md)
- [Debug an open source project with OSS-Fuzz — opensource.com](https://opensource.com/article/22/2/debug-open-source-project-oss-fuzz)
- [Verifying Signatures — Sigstore docs](https://docs.sigstore.dev/cosign/verifying/verify/)
- [cosign_verify-blob.md — sigstore/cosign](https://github.com/sigstore/cosign/blob/main/doc/cosign_verify-blob.md)
- [cosign_verify-attestation.md — sigstore/cosign](https://github.com/sigstore/cosign/blob/main/doc/cosign_verify-attestation.md)
- [cosign_verify.md — sigstore/cosign](https://github.com/sigstore/cosign/blob/main/doc/cosign_verify.md)
- [cosign_attest.md — sigstore/cosign](https://github.com/sigstore/cosign/blob/main/doc/cosign_attest.md)
- [Cosign Verification of npm Provenance, GitHub Artifact Attestations, and Homebrew Provenance — Sigstore Blog](https://blog.sigstore.dev/cosign-verify-bundles/)
- [Cosign 2.0 released — Sigstore Blog](https://blog.sigstore.dev/cosign-2-0-released/)
- [sigstore/cosign GitHub repository](https://github.com/sigstore/cosign)
- [How to Verify File Signatures with Cosign — Chainguard Academy](https://edu.chainguard.dev/open-source/sigstore/cosign/how-to-verify-file-signatures-with-cosign/)
- [Rust API Guidelines — Necessities (licensing)](https://rust-lang.github.io/api-guidelines/necessities.html)
- [MSRV Policies — rust-lang/api-guidelines #231](https://github.com/rust-lang/api-guidelines/discussions/231)
- [Rust Update Policy — Firefox Source Docs](https://firefox-source-docs.mozilla.org/writing-rust-code/update-policy.html)
- [RFC 2495 — min-rust-version](https://rust-lang.github.io/rfcs/2495-min-rust-version.html)
- [RFC 3537 — msrv-resolver](https://rust-lang.github.io/rfcs/3537-msrv-resolver.html)
- [Rust Project Primer — MSRV checks](https://rustprojectprimer.com/checks/msrv.html)
- [foresterre/cargo-msrv](https://github.com/foresterre/cargo-msrv)
- [cargo-msrv book — verify command](http://gribnau.dev/cargo-msrv/commands/verify.html)
- [Latest stable rust as MSRV — alexheretic gist](https://gist.github.com/alexheretic/d1e98d8433b602e57f5d0a9637927e0c)
- [time-rs/time discussion #535 — MSRV policy](https://github.com/time-rs/time/discussions/535)
- [apache/datafusion #9082 — MSRV policy discussion](https://github.com/apache/datafusion/issues/9082)
- [Rust MSRV policy and Linux Distros — Rust Internals](https://internals.rust-lang.org/t/rust-msrv-policy-and-linux-distros/17074)
- [RustCrypto/AEADs PR #351 — MSRV bumps treated as breaking](https://github.com/RustCrypto/AEADs/pull/351)
- [Rationale of Apache dual licensing — Rust Internals](https://internals.rust-lang.org/t/rationale-of-apache-dual-licensing/8952)
- [Google Open Source — Rust third-party guidance](https://opensource.google/documentation/reference/thirdparty/rust)
- [Cargo Vet — Introduction](https://mozilla.github.io/cargo-vet/)
- [Cargo Vet — Importing Audits](https://mozilla.github.io/cargo-vet/importing-audits.html)
- [Cargo Vet — How It Works](https://mozilla.github.io/cargo-vet/how-it-works.html)
- [Cargo Vet — Performing Audits](https://mozilla.github.io/cargo-vet/performing-audits.html)
- [Cargo Vet — Audit Criteria](https://mozilla.github.io/cargo-vet/audit-criteria.html)
- [Cargo Vet — Multiple Repositories](https://mozilla.github.io/cargo-vet/multiple-repositories.html)
- [mozilla/cargo-vet — registry.toml (canonical imports list)](https://github.com/mozilla/cargo-vet/blob/main/registry.toml)
- [mozilla/cargo-vet GitHub repo](https://github.com/mozilla/cargo-vet)
- [mozilla/supply-chain — aggregated Mozilla audits](https://github.com/mozilla/supply-chain)
- [cargo-vet 0.10.2 — docs.rs](https://docs.rs/crate/cargo-vet/latest)
- [Bytecode Alliance — Security and Correctness in Wasmtime](https://bytecodealliance.org/articles/security-and-correctness-in-wasmtime)
- [Pass-the-SALT 2023 — Rust Supply Chain Security talk](https://archives.pass-the-salt.org/Pass%20the%20SALT/2023/slides/PTS2023-Talk-11-rust-supply-chain-security.pdf)
- [OpenSSF Scorecard — scorecard.dev](https://scorecard.dev/)
- [ossf/scorecard](https://github.com/ossf/scorecard)
- [OpenSSF Scorecard — checks documentation](https://github.com/ossf/scorecard/blob/main/docs/checks.md)
- [OpenSSF Scorecard — project page](https://openssf.org/projects/scorecard/)
- [Introducing the OpenSSF Scorecard API — Endor Labs](https://www.endorlabs.com/learn/introducing-the-openssf-scorecard-api)
- [obi1kenobi/cargo-semver-checks](https://github.com/obi1kenobi/cargo-semver-checks)
- [cargo-semver-checks releases](https://github.com/obi1kenobi/cargo-semver-checks/releases)
- [cargo-semver-checks — docs.rs](https://docs.rs/cargo-semver-checks/latest/cargo_semver_checks/)
- [cargo-semver-checks — crates.io](https://crates.io/crates/cargo-semver-checks)
- [SemVer Compatibility — The Cargo Book](https://doc.rust-lang.org/cargo/reference/semver.html)
- [rust-lang/rust-semverver](https://github.com/rust-lang/rust-semverver)
- [rustsec/advisory-db](https://github.com/rustsec/advisory-db)
- [rustsec/rustsec — RustSec API & Tooling](https://github.com/rustsec/rustsec)
- [actions/dependency-review-action](https://github.com/actions/dependency-review-action)
- [step-security/harden-runner](https://github.com/step-security/harden-runner)
- [StepSecurity Harden Runner docs](https://docs.stepsecurity.io/harden-runner)
- [StepSecurity blog — Windows + macOS support for Harden Runner](https://www.stepsecurity.io/blog/harden-runner-now-supports-windows-and-macos-github-actions-runners)
- [release-plz quickstart](https://release-plz.dev/docs/github/quickstart)
- [rust-lang/rust#34902 — reproducible builds tracking issue](https://github.com/rust-lang/rust/issues/34902)
- [rust-lang/cargo#16691 — reproducible-builds-related cargo PR](https://github.com/rust-lang/cargo/pull/16691)
