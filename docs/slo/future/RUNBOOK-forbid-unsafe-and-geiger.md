# `forbid(unsafe_code)` Lock-Down + `cargo-geiger` Supply-Chain Visibility — SunLitSecurityLibraries (AI-First Runbook v4)

> **Purpose**: Lock the existing `#![forbid(unsafe_code)]` posture into the published-crate contract via a regression test, extend it to the one missing crate (`secure_smoke_service`), and add `cargo-geiger` to the supply-chain CI lane to make transitive `unsafe` usage visible and budgeted.
> **Audience**: AI coding agents first, humans second.
> **Core philosophy**: Lock down what's true today. Encode invariants so they cannot regress silently. Make transitive risk visible.
> **Prerequisite reading**: [README.md](../../../README.md), [ARCHITECTURE.md](../../../ARCHITECTURE.md), [`docs/slo/research/forbid-unsafe-and-geiger/`](../research/forbid-unsafe-and-geiger/), [`docs/slo/idea/forbid-unsafe-and-geiger.md`](../idea/forbid-unsafe-and-geiger.md), [v4 template](../templates/runbook-template_v_4_template.md). Sections 4 / 6 / 7 / 8 / 11 / 12 / 13–14 of v4 apply.

---

## 1. Runbook Metadata

| Field | Value |
|---|---|
| Runbook ID | `forbid-unsafe-and-geiger` |
| Project name | SunLitSecurityLibraries |
| Primary stack | Rust 2021 + Cargo workspace |
| Primary package/app names | All published crates + `secure_smoke_service` |
| Prefix for tests and lesson files | `fug` |
| Default unit test command | `cargo test --workspace` |
| Default integration/BDD test command | `cargo test --workspace --all-features` |
| Default E2E/runtime validation command | `cargo test --workspace --test 'e2e_*'` |
| Default build/boot command | `cargo build --workspace --all-features` |
| Default formatter command | `cargo fmt --all -- --check` |
| Default static analysis / lint command | `cargo clippy --workspace --all-targets --all-features -- -D warnings` |
| Default dependency / security audit command | `cargo audit && cargo deny check && cargo vet` |
| Geiger command (M2) | `cargo geiger --workspace --all-features --output-format Json --update-readme` (exact form pinned in M2) |
| Default debugger | `cargo expand -p <crate>` for macro inspection; `cargo test -- --nocapture` |
| Allowed new dependencies by default | `none` (CI tooling installed in workflow only — `cargo-geiger` via `cargo install --locked --version <X.Y.Z> cargo-geiger`) |
| Schema/config migration allowed by default | `no` |
| Public interfaces stable by default | `yes` |

### Public interfaces that must remain stable unless explicitly listed otherwise

- All published crate `lib.rs` first-line attributes must remain `#![forbid(unsafe_code)]`. (M1 codifies this as a regression test.)
- All published crate types and traits.

---

## 2. Milestone Tracker

| # | Milestone | Status | Started | Completed | Lessons File | Completion Summary |
|---|---|---|---|---|---|---|
| 1 | Verify forbid(unsafe_code) on every published crate; add to `secure_smoke_service`; add regression test | `done` | 2026-05-05 | 2026-05-05 | [`docs/slo/lessons/fug-m1.md`](../lessons/fug-m1.md) | [`docs/slo/completion/fug-m1.md`](../completion/fug-m1.md) — all workspace crates `forbid(unsafe_code)`; regression-tested in `crates/security_core/tests/no_unsafe_code.rs`. Closes #16. |
| 2 | Add `cargo-geiger` to supply-chain CI lane; publish workspace unsafe number; document threshold | `not_started` | | | | |

---

## 3. End-to-End Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│           Supply-chain CI lane (existing) + new geiger step                  │
│                                                                              │
│   PR opens                                                                   │
│     │                                                                        │
│     ▼                                                                        │
│   .github/workflows/ci.yml ──── existing supply-chain job                    │
│     │                                                                        │
│     ├─ cargo audit         (existing)                                        │
│     ├─ cargo deny check    (existing)                                        │
│     ├─ cargo vet           (existing)                                        │
│     └─ cargo geiger        ─── NEW M2: workspace unsafe count, JSON artifact │
│                                                                              │
│   Per-crate compile-time invariant:                                          │
│     #![forbid(unsafe_code)] in every published crate root                    │
│     enforced by tests/no_unsafe_code.rs (NEW M1) — fails build if removed    │
│                                                                              │
│   README badge: `unsafe (workspace, all-features): N` (NEW M2)               │
│                                                                              │
│   Legend: ─── existing   - - - new                                           │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Component Summary Table

| Component | Responsibility | Existing/New/Changed | Milestone | Key Interfaces |
|---|---|---|---|---|
| Per-crate `#![forbid(unsafe_code)]` | Compile-time guarantee | existing on 13/14 crates; M1 adds to `secure_smoke_service` | M1 | rustc lint |
| `tests/no_unsafe_code.rs` (workspace-level integration test) | Regression test that lib-roots still have `#![forbid(unsafe_code)]` | new | M1 | `cargo test` |
| `cargo geiger` workspace step | CI step measuring transitive unsafe | new | M2 | GH Actions |
| `output/cargo-geiger.json` | Build artifact (CI) | new | M2 | (artifact) |
| README "Unsafe budget" line | User-facing doc of the workspace number + threshold | new | M2 | README |

---

## 4. Carmack-Style Development Best Practices

Inherits §4 of [v4 template](../templates/runbook-template_v_4_template.md). Project-specific bindings: same as PQ runbook §4.

**Resource bounds**: M2 introduces a documented "transitive unsafe budget" — the current measured value + small headroom — published as an artifact threshold. The threshold is informational (CI advisory) until a follow-up promotes it.

**Invariants this runbook adds**:
- Every published crate's `lib.rs` begins with `#![forbid(unsafe_code)]` (encoded as a regression test).
- The supply-chain CI lane publishes a `cargo-geiger` JSON artifact on every PR.
- The README's "Unsafe budget" line states the workspace number and the threshold.

---

## 5. High-Level Design for State Modeling / Formal Verification

`N/A — this runbook is documentation + lint + CI configuration. There is no concurrent state, no protocol, no race. Existing tests + the new regression test cover the property.`

---

## 6–8. Global Execution / Pre-Milestone / Post-Milestone Rules

Inherits §6–8 of [v4 template](../templates/runbook-template_v_4_template.md).

---

## 9. Background Context

### Current State

Every published crate (`security_core`, `secure_errors`, `security_events`, `secure_boundary`, `secure_authz`, `secure_data`, `secure_output`, `secure_identity`, `secure_device_trust`, `secure_network`, `secure_resilience`, `secure_privacy`) already begins its `lib.rs` with `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]`. `secure_reference_service` (private) also has `#![forbid(unsafe_code)]`. `secure_smoke_service` (private workspace crate) is the only crate without the attribute. There are no `unsafe` blocks anywhere in `crates/*/src/`. There is no `cargo-geiger` step in CI.

### Problem

1. **The forbid posture is unstated as a contract** — a future contributor could remove `#![forbid(unsafe_code)]` from any crate and no test would catch it. The compile-time guarantee is invisible to PR review unless someone reads the diff.
2. **`secure_smoke_service` is missing the attribute** — even though it has no `unsafe`, the absence of the attribute leaves the door open.
3. **Transitive unsafe is unmeasured** — SunLit cannot answer "how much unsafe is in your dependency tree?" without running `cargo-geiger` ad-hoc. A published number lets consumers compare and lets us notice regressions.
4. **No threshold** — without a documented baseline, "the geiger number ticked up" produces no signal.

### Target Architecture

See §3 above. End state: every published crate's `forbid(unsafe_code)` is regression-tested; `secure_smoke_service` has the attribute; `cargo-geiger` runs in CI on every PR; README publishes the workspace number; threshold documented.

### Key Design Principles

1. **Lock the win** — the project already has `forbid(unsafe_code)` as the posture; M1's job is to make removal an automated failure, not a code review judgment call.
2. **Stay on `cargo-geiger`** — research verdict: active but partial maintenance; no drop-in successor; `cargo-indicate` is complementary, not a substitute. Pin the version.
3. **Pin the geiger invocation** — `--all-features` is the official number (worst-case). Pin the version and the flag set in CI so the published number is reproducible.
4. **`tokio::pin!` is a known forbid-breaker** — research confirmed. SunLit's current code does not use it; the regression test must keep that property explicit (a doc comment in `tests/no_unsafe_code.rs` calls out the `tokio::pin!` substitution rule).
5. **OSS docs are first-class output** — every milestone updates README + CHANGELOG; M2 adds a dev-guide page describing the unsafe-budget posture.
6. **Release notes describe what consumers gain** — "every published SunLit crate is `forbid(unsafe_code)` and a CI test catches regressions" is the line, not "added a regression test."
7. **Threshold starts informational** — promotion to blocking is a follow-up runbook after stability is observed for ≥1 release cycle.

### What to Keep

- All existing `forbid(unsafe_code)` attributes — verified, not changed.
- Existing CI lanes (`ci.yml`, `codeql.yml`, `dastardly.yml`, `native-device-trust-conformance.yml`, `release-sign.yml`, `semgrep.yml`).
- Existing supply-chain tooling (`cargo audit`, `cargo deny`, `cargo vet`).

### What to Change

- **`crates/secure_smoke_service/src/lib.rs`** — add `#![forbid(unsafe_code)]` at the top (only).
- **`tests/no_unsafe_code.rs`** at workspace root — NEW: regression test verifying every published crate's lib.rs begins with `#![forbid(unsafe_code)]`.
- **`Cargo.toml`** at workspace root — declare `tests/no_unsafe_code.rs` as an integration test of the root package (existing root crate is `sunlit-orchestrate-tests`-style or similar; check shape).
- **`.github/workflows/ci.yml`** — extend the supply-chain job with a `cargo-geiger` step.
- **`scripts/audit.sh`** — add `cargo-geiger` invocation alongside existing tools (advisory; same flag set as CI).
- **`scripts/audit.ps1`** — Windows parity.
- **`README.md`** — add an "Unsafe (workspace, all features)" line / badge in the supply-chain section.
- **`docs/dev-guide/unsafe-budget.md`** — NEW (M2): one page explaining the posture, the published number, the threshold, the promotion plan.
- **`CHANGELOG.md`** — entry per milestone.

### Global Red Lines

Inherits §9 of v4. Plus:

- No new dependencies on `tokio::pin!` or `pin-project` (keep the macro-expansion landscape clean — research confirms `tokio::pin!` would break `forbid(unsafe_code)`).
- No silent removal of `forbid(unsafe_code)` from any crate.
- No "FIPS / regulatory" claim without backing — the unsafe-budget doc says "memory-safety attestation surface" not "FIPS compliance."

---

## 10. Carry-forward from prior retros

(Empty.)

---

## 11–14. BDD / Dependency / Evidence / Self-Review

Inherits §11–14 of v4.

---

## 15–16. Lessons / Completion Templates

Standard v4. Lessons → `docs/slo/lessons/fug-m<N>.md`; completion → `docs/slo/completion/fug-m<N>.md`.

---

## 17. Milestone Plan

### Milestone 1 — Verify, extend, regression-test

**Goal**: Every published crate plus `secure_smoke_service` has `#![forbid(unsafe_code)]` at the lib-root, and a workspace-level integration test fails the build if any crate's attribute is removed. Confirm zero `unsafe` blocks across the workspace.

**Carmack-style reliability goal**: Make invalid states unrepresentable (the regression test makes "removed `forbid` attr" an explicit build failure); static analysis mandatory (the test *is* the static analysis, plus existing clippy lint chain).

**Important design rule**: The regression test reads each crate's `lib.rs`, asserts the first non-comment line is exactly `#![forbid(unsafe_code)]` (or contains it within the first N lines, allowing for outer attributes / shebangs). Document the precise rule.

**Refactor budget**: `Minimal local refactor permitted in listed files only`.

#### Contract Block

| Field | Value |
|---|---|
| Inputs | Existing crate `lib.rs` files; future contributor PRs |
| Outputs | `secure_smoke_service` gains the attribute; new regression test in `tests/no_unsafe_code.rs` at workspace root; CI catches removal regressions |
| Interfaces touched | None public — the change is a compile-time attribute and an integration test |
| Files allowed to change | `crates/secure_smoke_service/src/lib.rs` (add the attribute as the first line); `tests/no_unsafe_code.rs` (NEW at workspace root); `Cargo.toml` at workspace root if the integration test needs explicit declaration; `CHANGELOG.md`; `README.md` (mention in supply-chain section); `docs/dev-guide/unsafe-budget.md` (NEW skeleton — completed in M2) |
| Files to read before changing anything | All `crates/*/src/lib.rs` first 20 lines; root `Cargo.toml`; existing tests at workspace root |
| New files allowed | `tests/no_unsafe_code.rs`, `docs/dev-guide/unsafe-budget.md` |
| New dependencies allowed | `none` (the test uses std only) |
| Migration allowed | `no` |
| Compatibility commitments | All existing tests remain green. All existing CI lanes remain green. Build behaviour unchanged for downstream consumers. |
| Resource bounds introduced/changed | Test reads a small fixed list of crates (≤14); per-crate read is a head-of-file (≤2 KB). Bounded. |
| Invariants/assertions required | (1) Every published crate's `lib.rs` contains `#![forbid(unsafe_code)]` within its first 10 lines, before any item declaration. (2) `secure_smoke_service/src/lib.rs` likewise. (3) Test fails with a clear message naming the offending crate if the attribute is missing. |
| Debugger / inspection expectation | Test failure prints a diff-shaped message: "expected `#![forbid(unsafe_code)]` in crates/<X>/src/lib.rs within first 10 lines; not found." `cargo expand --workspace --all-features` confirms no macro expansion adds an `unsafe`. |
| Static analysis gates | All v4 §4.2 gates plus the new regression test. |
| Forbidden shortcuts | No "TODO: enforce later." No relaxing `forbid` to `deny` to satisfy a macro. No `#[allow(unsafe_code)]` anywhere. |
| Data classification | `Public` |
| Proactive controls in play | `C2` (Frameworks/Libraries — Rust's unsafe lint as a verifier). |
| Abuse acceptance scenarios | `tm-fug-abuse-1`: a future contributor removes `#![forbid(unsafe_code)]` from any crate (deliberately or by accident in a copy-paste lib refactor) → workspace test fails, CI blocks merge. `tm-fug-abuse-2`: a future contributor adds an `unsafe` block under `#[allow(unsafe_code)]` → `forbid` cannot be locally overridden; rustc rejects the file at compile. (No code change needed for tm-fug-abuse-2; it's the existing `forbid` semantics — the regression test exists to keep `forbid` itself.) |

#### Out of Scope / Must Not Do

- M2's geiger work.
- Promoting any threshold to blocking.
- Adding `forbid(unsafe_code)` to `secure_reference_service` (already has it per code reads).
- Touching any production code beyond the smoke-service lib.rs addition.

#### Step-by-Step

1. Read every `crates/*/src/lib.rs` head; confirm only `secure_smoke_service` is missing the attribute.
2. Add `#![forbid(unsafe_code)]` as the first line of `crates/secure_smoke_service/src/lib.rs`.
3. Write `tests/no_unsafe_code.rs` as a workspace integration test. The test enumerates the crate list (or reads `Cargo.toml` for it) and asserts the attribute exists.
4. Run the test against current code; confirm it passes.
5. Mutation-test the test: temporarily remove `#![forbid(unsafe_code)]` from one crate; confirm the test fails with a clear message; restore.
6. Run formatter, lint, full tests, audit.
7. Write CHANGELOG entry, README mention, dev-guide skeleton.
8. Smoke + Self-Review.

#### BDD Acceptance Scenarios

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| every published crate has forbid | happy path | current workspace | run `cargo test --test no_unsafe_code` | passes |
| smoke service has forbid | happy path | post-M1 patch applied | inspect `crates/secure_smoke_service/src/lib.rs` first line | matches `#![forbid(unsafe_code)]` |
| forbid removal caught | abuse case (`tm-fug-abuse-1`) | mutate one crate's lib.rs to drop the attribute | run `cargo test --test no_unsafe_code` | fails with named-crate error |
| build behaviour unchanged | compatibility | existing downstream consumer test | `cargo build --workspace --all-features` | succeeds; same warnings/output |
| no `unsafe` blocks anywhere | invariant | current workspace | `git grep -E "^\s*unsafe " crates/` | empty result |
| `cargo expand` shows no macro-introduced unsafe | invariant / debugger | `cargo expand -p <each-crate>` | scan output | no `unsafe` keyword |

#### Documentation requirements (M1-specific)

- README's supply-chain section gains a one-line statement: "Every published crate is `#![forbid(unsafe_code)]`; regression-tested by `tests/no_unsafe_code.rs`."
- CHANGELOG entry: "All published SunLit crates are now `#![forbid(unsafe_code)]` and the posture is regression-tested. `secure_smoke_service` (private) joins the same posture."
- `docs/dev-guide/unsafe-budget.md` skeleton (completed in M2).

(Files Allowed To Change, Regression Tests, Compatibility Checklist, E2E, Smoke, Evidence Log, DoD per v4 template.)

---

### Milestone 2 — `cargo-geiger` in supply-chain CI; published workspace number; documented threshold

**Goal**: `cargo-geiger` runs on every PR via the supply-chain CI lane, publishes a JSON artifact, and the README has an "Unsafe (workspace, all features): N" line. The dev-guide page describes the threshold and the promotion plan.

**Carmack-style reliability goal**: Bounded resources (the geiger invocation has a CI runtime cap; the published number is a budget); static analysis mandatory (geiger *is* the analysis); no silent failure (geiger output is published as an artifact regardless of pass/fail).

**Important design rule**: Pin the geiger version in CI. Pin the flag set. Pin the output format. The published number must be reproducible from the same SunLit commit + same geiger version + same flags.

**Refactor budget**: `Minimal local refactor permitted in listed files only`.

#### Contract Block

| Field | Value |
|---|---|
| Inputs | Workspace dependency tree (`cargo metadata` resolved with `--all-features`) |
| Outputs | `output/cargo-geiger.json` artifact on every PR; README "Unsafe budget" line; threshold documented |
| Interfaces touched | `.github/workflows/ci.yml` supply-chain job; `scripts/audit.sh`/`audit.ps1`; README; new dev-guide page |
| Files allowed to change | `.github/workflows/ci.yml` (extend supply-chain job), `scripts/audit.sh`, `scripts/audit.ps1`, `README.md`, `docs/dev-guide/unsafe-budget.md` (complete from M1 skeleton), `CHANGELOG.md`, `.gitignore` (cover `output/cargo-geiger.json` if not already) |
| Files to read before changing anything | M1 lessons; `[research synthesis](../research/forbid-unsafe-and-geiger/synthesis.md)`; existing `.github/workflows/ci.yml` supply-chain job; `scripts/audit.sh` |
| New files allowed | (none beyond M1 skeletons completing) |
| New dependencies allowed | `cargo-geiger` (CI install only, pinned version per research). No runtime deps. |
| Migration allowed | `no` |
| Compatibility commitments | Existing supply-chain job's `cargo audit` / `cargo deny` / `cargo vet` steps unchanged. CI-job runtime stays within current cap (cargo-geiger adds ≤5 min on a warm cache). |
| Resource bounds introduced/changed | CI cap for geiger step = 10 min (configurable). Threshold = current measured baseline + 10% headroom (informational, advisory). |
| Invariants/assertions required | (1) Every PR produces a `cargo-geiger.json` artifact. (2) The artifact is parseable and contains a `total_unsafe_count` field. (3) The README number matches the artifact's value as of the last main-branch run. (4) The threshold is documented and is monotonically non-decreasing during this milestone (informational only — a separate runbook promotes to blocking). |
| Debugger / inspection expectation | The CI artifact is downloadable; the dev-guide describes how to interpret it locally. |
| Static analysis gates | All v4 §4.2 gates; **plus** the geiger step itself; **plus** `cargo deny check licenses` to confirm `cargo-geiger`'s license is acceptable for CI installation. |
| Forbidden shortcuts | No silently raising the threshold without documenting why. No "advisory means we ignore it." No skipping the artifact upload. |
| Data classification | `Public` |
| Proactive controls in play | `C2` (Leverage Security Frameworks — geiger as supply-chain verifier), `C9` (Implement Security Logging — CI artifact is evidence). |
| Abuse acceptance scenarios | `tm-fug-abuse-3`: a transitive dep introduces a large amount of new unsafe → geiger number jumps; CI artifact records the delta; reviewer can see the diff in the PR. `tm-fug-abuse-4`: someone tries to silently raise the threshold to mask a regression → the threshold sits in the dev-guide doc + README; PR diff makes the change visible. |

#### Out of Scope / Must Not Do

- Promoting the threshold to blocking.
- Replacing `cargo-geiger` with a successor (research recommends staying on it for now).
- Adding `cargo-indicate` or other complementary tools (separate runbook).

#### Step-by-Step

1. Read M1 lessons; read research synthesis for invocation form + version pin.
2. Run `cargo geiger --workspace --all-features --output-format Json` locally; record the baseline number.
3. Add the step to `.github/workflows/ci.yml` supply-chain job — installed via `cargo install --locked --version <X.Y.Z>`; runs against the workspace; uploads `output/cargo-geiger.json` as an artifact.
4. Mirror the invocation in `scripts/audit.sh` / `scripts/audit.ps1`.
5. Update README with the workspace number and threshold + link to dev-guide.
6. Complete `docs/dev-guide/unsafe-budget.md`: posture, published number, threshold rationale, promotion plan.
7. Run formatter, lint, full tests, audit chain, and a CI dry-run.
8. CHANGELOG entry.
9. Smoke + Self-Review.

#### BDD Acceptance Scenarios

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| geiger runs on PR | happy path | a PR is opened | CI runs the supply-chain job | `cargo-geiger.json` artifact uploaded |
| README number reproducible | invariant | same SunLit commit, same geiger version, same flags | re-run locally | same `total_unsafe_count` |
| threshold documented | invariant | dev-guide page exists | read `docs/dev-guide/unsafe-budget.md` | threshold present, with rationale |
| threshold-raise visible | abuse case (`tm-fug-abuse-4`) | PR raises the threshold | reviewer reads diff | change visible in `unsafe-budget.md` + README |
| existing supply-chain steps unchanged | compatibility | `cargo audit` / `cargo deny` / `cargo vet` | CI runs supply-chain job | each step still passes per existing policy |

(Files Allowed, Regression, Compatibility, E2E, Smoke, Evidence Log, DoD per v4.)

#### Documentation requirements (M2-specific)

- README "Unsafe (workspace, all features)" line under the supply-chain section.
- `docs/dev-guide/unsafe-budget.md` complete: posture, current number, threshold + headroom, promotion plan.
- CHANGELOG: "Supply-chain CI now runs cargo-geiger on every PR and publishes a JSON artifact. The README states the workspace's transitive `unsafe` number; the threshold is informational (advisory) until a follow-up runbook promotes it to blocking."

---

## 18. Documentation Update Table

| Milestone | ARCHITECTURE.md Update | README.md Update | .gitignore Update | Other Docs |
|---|---|---|---|---|
| 1 | (no change) | Supply-chain section gains forbid-line | — | `docs/dev-guide/unsafe-budget.md` (NEW skeleton); CHANGELOG |
| 2 | (no change) | "Unsafe (workspace, all features): N" line + threshold link | `output/cargo-geiger.json` ignored | `docs/dev-guide/unsafe-budget.md` complete; CHANGELOG |

---

## 19. Optional Fast-Fail Review Prompt for Agents

> Restate the milestone goal, allowed files, forbidden changes, compatibility, dependencies, regression tests, CI step shape, threshold rule, and Definition of Done. Cite the research synthesis row for any tooling or version choice.

---

## 20. Source Basis

This runbook is a v4 instance authored against [`docs/slo/templates/runbook-template_v_4_template.md`](../templates/runbook-template_v_4_template.md). Research basis: [`docs/slo/research/forbid-unsafe-and-geiger/dossier.md`](../research/forbid-unsafe-and-geiger/dossier.md) (35 sources, `incomplete:false`; verdicts: cargo-geiger active-but-partial maintenance, no drop-in successor, stay with it; `tokio::pin!` is a known forbid-breaker — not used in SunLit's tree, regression test enforces). Idea basis: [`docs/slo/idea/forbid-unsafe-and-geiger.md`](../idea/forbid-unsafe-and-geiger.md). Code-side discovery: every published crate already has `#![forbid(unsafe_code)]`; only `secure_smoke_service` is missing — runbook scope reduces accordingly.
