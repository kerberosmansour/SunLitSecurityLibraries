# Formal Verification (Kani + TLA+) — SunLitSecurityLibraries (AI-First Runbook v4)

> **Purpose**: Add proof-grade evidence to SunLit's adversarial-testing story: Kani-verified safety invariants in `secure_authz`, `secure_boundary`, `secure_data`, `secure_errors`; a new TLA+-verified `secure_resilience::circuit_breaker` module; a TLA+-verified design for `secure_identity` session+step-up. Two advisory CI lanes (`kani.yml`, `tla.yml`).
> **Audience**: AI coding agents first, humans second.
> **Core philosophy**: Prefer a small number of load-bearing proofs over a wide ineffective sweep. Prefer narrative counterexamples over raw TLC traces. Prefer advisory CI promotion-after-stability over blocking-on-day-one.
> **Prerequisite reading**: [README.md](../../../README.md), [ARCHITECTURE.md](../../../ARCHITECTURE.md), [`docs/slo/research/formal-verification-kani-tla/`](../research/formal-verification-kani-tla/) (40 sources, `incomplete:false`), [`docs/slo/idea/formal-verification-kani-tla.md`](../idea/formal-verification-kani-tla.md), [v4 template](../templates/runbook-template_v_4_template.md). Sections 4 / 6 / 7 / 8 / 11 / 12 / 13–14 of v4 apply to every milestone.

---

## 1. Runbook Metadata

| Field | Value |
|---|---|
| Runbook ID | `formal-verification-kani-tla` |
| Project name | SunLitSecurityLibraries |
| Primary stack | Rust 2021 + Cargo + Kani (model-checking.github.io/kani) + TLA+ Tools (TLC) |
| Primary package/app names | `secure_authz`, `secure_boundary`, `secure_data`, `secure_errors`, `secure_resilience`, `secure_identity` |
| Prefix for tests and lesson files | `fv` |
| Default unit test command | `cargo test --workspace` |
| Default integration/BDD test command | `cargo test --workspace --all-features` |
| Default E2E/runtime validation command | `cargo test --workspace --test 'e2e_*'` |
| Default build/boot command | `cargo build --workspace` |
| Default formatter command | `cargo fmt --all -- --check` |
| Default static analysis / lint command | `cargo clippy --workspace --all-targets --all-features -- -D warnings` |
| Default dependency / security audit command | `cargo audit && cargo deny check && cargo vet` |
| Default Kani command | `cargo kani -p <crate> --harness <name>` (15-min CI cap per research) |
| Default TLC command | `~/.sldo/tla/tlc -workers auto -config specs/<name>.cfg specs/<name>.tla` (10-min CI cap) |
| Default debugger | `cargo test -- --nocapture`, `lldb`, Kani's `--visualize` for counterexamples, TLC trace files |
| Allowed new dependencies by default | `none` |
| Schema/config migration allowed by default | `no` |
| Public interfaces stable by default | `yes` |

### Public interfaces that must remain stable unless explicitly listed otherwise

- All currently-published `secure_authz`, `secure_boundary`, `secure_data`, `secure_errors`, `secure_identity` types and traits.
- Existing `secure_resilience::{IntegrityCheck, RaspEngine, EnvironmentSignal, ...}` — M4 *adds* a `circuit_breaker` module without changing them.

---

## 2. Milestone Tracker

| # | Milestone | Status | Started | Completed | Lessons File | Completion Summary |
|---|---|---|---|---|---|---|
| 1 | Kani toolchain bootstrap + first proof (`secure_data` non-zero nonce) + advisory CI lane | `done` | 2026-05-06 | 2026-05-06 | [`docs/slo/lessons/fv-m1.md`](../lessons/fv-m1.md) | [`docs/slo/completion/fv-m1.md`](../completion/fv-m1.md) — `crates/secure_data/src/proofs.rs` (`#[cfg(kani)]`) ships `nonce_non_zero` + `aes_256_gcm_nonce_len_is_12`; advisory CI lane (15-min cap). Closes #11. |
| 2 | Kani proofs for `secure_authz` deny-by-default + `secure_boundary` depth/size/field limits | `done` | 2026-05-06 | 2026-05-06 | [`docs/slo/lessons/fv-m2.md`](../lessons/fv-m2.md) | [`docs/slo/completion/fv-m2.md`](../completion/fv-m2.md) — discriminant + limit-rejection invariants proven within bounds; matrix extended to authz+boundary; Kani pin bumped to 0.67.0 for current dependency compatibility. Closes #12. |
| 3 | Kani proofs for `secure_data` nonce-uniqueness within path + `secure_errors` public-body-no-leak | `done` | 2026-05-06 | 2026-05-06 | [`docs/slo/lessons/fv-m3.md`](../lessons/fv-m3.md) | [`docs/slo/completion/fv-m3.md`](../completion/fv-m3.md) — per-algorithm nonce-length invariants on `secure_data`; status-range + static-code + whitelist proofs on `secure_errors`. Closes #13. |
| 4 | Add `secure_resilience::circuit_breaker` module + TLA+ spec + verified-design doc | `not_started` | | | | |
| 5 | TLA+ spec for `secure_identity` session+step-up + verified-design doc + `tla.yml` CI lane | `not_started` | | | | |

---

## 3. End-to-End Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│              SunLit formal-verification posture (end state)                  │
│                                                                              │
│  Code-level (Kani — bit-precise model checking, advisory CI 15-min cap)      │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  crates/secure_authz/proofs/  — deny-by-default invariant              │  │
│  │  crates/secure_boundary/proofs/ — depth/size/field limits never exceed │  │
│  │  crates/secure_data/proofs/   — nonce non-zero + uniqueness in path    │  │
│  │  crates/secure_errors/proofs/ — public body never embeds internal text │  │
│  │     │                                                                  │  │
│  │     ▼  cargo kani  (advisory in M1–M3, promotion gate in retro)        │  │
│  │  .github/workflows/kani.yml  (15-min cap, advisory)                    │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  Design-level (TLA+ / TLC — protocol-level reasoning, advisory CI)           │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  specs/CircuitBreaker.tla     ─── new (M4)                             │  │
│  │  specs/SessionStepUp.tla      ─── new (M5)                             │  │
│  │  specs/NativeDeviceTrust.tla  ─── existing (out of scope, untouched)   │  │
│  │     │                                                                  │  │
│  │     ▼  TLC at declared bounds  (Naive variant first; Hardened second)  │  │
│  │  docs/slo/design/circuit-breaker-verified.md  (M4)                     │  │
│  │  docs/slo/design/session-step-up-verified.md  (M5)                     │  │
│  │  .github/workflows/tla.yml   (10-min cap, advisory)                    │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  Runtime impact: secure_resilience gains a circuit_breaker module (M4)       │
│      └── new public API (closed/open/half-open SM, configurable thresholds,  │
│          single-probe rule, observability hooks)                             │
│                                                                              │
│  Legend: ─── existing   - - - new   ▶ data flow                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Component Summary Table

| Component | Responsibility | Existing/New/Changed | Milestone | Key Interfaces |
|---|---|---|---|---|
| `crates/secure_data/proofs/` | Kani harnesses for nonce non-zero + uniqueness | new | M1, M3 | `cargo kani -p secure_data` |
| `crates/secure_authz/proofs/` | Kani harness for deny-by-default | new | M2 | `cargo kani -p secure_authz` |
| `crates/secure_boundary/proofs/` | Kani harnesses for limits | new | M2 | `cargo kani -p secure_boundary` |
| `crates/secure_errors/proofs/` | Kani harness for `into_response_parts` no-leak | new | M3 | `cargo kani -p secure_errors` |
| `secure_resilience::circuit_breaker` | New Rust module: closed/open/half-open SM + single-probe | new | M4 | `CircuitBreaker::call`, `CircuitBreakerPolicy`, `CircuitBreakerObserver` |
| `specs/CircuitBreaker.tla` + `.cfg` | TLA+ spec for circuit-breaker invariants | new | M4 | TLC |
| `specs/SessionStepUp.tla` + `.cfg` | TLA+ spec for session+step-up invariants | new | M5 | TLC |
| `docs/slo/design/circuit-breaker-verified.md` | Verified-design doc for the new circuit-breaker module | new | M4 | (doc) |
| `docs/slo/design/session-step-up-verified.md` | Verified-design doc for session+step-up | new | M5 | (doc) |
| `.github/workflows/kani.yml` | Advisory CI lane for Kani proofs | new | M1 (set up), extended through M3 | GH Actions |
| `.github/workflows/tla.yml` | Advisory CI lane for TLC | new | M5 | GH Actions |
| `docs/dev-guide/formal-verification.md` | Consumer-facing dev guide explaining what is proven and how to reuse | new | M5 | (doc) |

### Data Flow Summary

| Flow | From | To | Protocol/Mechanism | Bounded? | Failure Mode | Milestone |
|---|---|---|---|---|---|---|
| Kani proof execution (CI) | `cargo kani` | GH Actions | bounded model checking | yes (loop unwinds + bounded inputs) | advisory: lane fails as a soft signal | M1, extended M2/M3 |
| TLC model check (CI) | TLA+ tools | GH Actions | exhaustive state-space exploration at declared bound | yes (declared bounds) | advisory; explosion → flag, not block | M5 |
| Circuit-breaker request | application | `secure_resilience::circuit_breaker::CircuitBreaker::call` | sync wrapper around an `FnOnce` closure | yes (single-probe in half-open) | open-state → returns immediately with `CircuitOpen` error; tripped via threshold | M4 |
| Session step-up check | application | `secure_identity::step_up` | trait call | yes (per-session) | denied → structured error; never silent | M5 (pre-existing; M5 verifies design) |

---

## 4. Carmack-Style Development Best Practices

Inherits §4 of [v4 template](../templates/runbook-template_v_4_template.md). Project-specific bindings:

| Requirement | Tool/Command |
|---|---|
| Kani install | `cargo install --locked kani-verifier && cargo kani setup` (M1 sets the version pin in `rust-toolchain` or workspace docs) |
| TLC install | Per [`/slo-tla` SKILL.md](~/.claude/skills/slo-tla/SKILL.md) — `~/.sldo/tla/tla2tools.jar`, pinned via `tools.toml` |
| Lint per crate | `cargo clippy -p <crate> --all-targets --all-features -- -D warnings` |
| Static analyzer for proofs | `cargo kani` itself catches assertion violations and overflows |
| Property tests | (existing) `cargo test -p <crate> -- prop_` |
| Geiger | (existing) `cargo geiger -p <crate>` (extends in the [forbid-unsafe-and-geiger runbook](RUNBOOK-forbid-unsafe-and-geiger.md)) |

**Resource bounds for this runbook**:
- Kani CI lane: 15-minute soft cap per research; advisory in M1–M3, promotion-to-blocking is a follow-up in lessons.
- TLC CI lane: 10-minute soft cap per research; advisory through M4–M5.
- TLC bounds per spec: Circuit breaker — 3 actors, 5 calls, 2 failure injections; Session step-up — 2 sessions, 3 actions, 2 expirations. Bounds re-stated in each verified-design doc.

**Invariants this runbook adds (all proven, not asserted at runtime)**:
- `secure_authz`: `Authorizer::authorize(subject, action, resource)` returns `Decision::Deny { reason }` whenever no policy in the engine matches the (subject, action, resource) triple. Proven within Kani's bound on policy-set size.
- `secure_boundary`: `SecureJson<T>` deserialization rejects any input where depth > configured limit, field count > configured limit, or body size > configured limit. Proven within Kani's bound on input size.
- `secure_data`: nonce construction at the v1 (AEAD) path is non-zero and unique within a single encrypt call. AEAD itself is axiomatised per Kani research yellow-flag.
- `secure_errors::http::into_response_parts`: the public response body never embeds the underlying error's `Display` text or the internal `dep:` field. Proven within Kani's bound on the input error variant set.
- `secure_resilience::circuit_breaker`: TLC proves no double-probe in half-open; no `Closed` after a tripping event without observable reset; single-probe rule never violated under the modelled interleavings.
- `secure_identity` (existing code): TLC proves no privileged action reachable from unauthenticated state; expired sessions never reusable; step-up window correctly enforced.

---

## 5. High-Level Design for State Modeling / Formal Verification

Two TLA+ designs land in this runbook (M4 and M5). M1–M3 are Kani-only. The TLA+ section below is shared scaffolding; each verified-design doc fills concrete bounds.

### 5.1 System Goal

Two protocol-level state machines must be sound: (a) a circuit breaker (M4) that mediates downstream failures without ever wedging in half-open or producing two simultaneous probes; (b) a session+step-up flow (M5) that never lets an unauthenticated principal reach a privileged action and never lets an expired session be re-used.

### 5.2 Main Components

| Component | Protocol Role | Key State (durable / volatile) | Visible Actions |
|---|---|---|---|
| `CircuitBreaker` (M4) | Failure-isolation guard for a single downstream | `state ∈ {Closed, Open, HalfOpen}`, `failure_count`, `last_open_time`, `probe_inflight: BOOLEAN` | `Call(req)` → success/failure/short-circuit; `OnSuccess`, `OnFailure`, `Tick` (clock) |
| `Session` (M5, existing code) | Authenticated user session lifecycle | `auth_state ∈ {Anonymous, Authenticated, StepUpRequired, StepUpSatisfied, Expired}`, `expires_at` | `Login`, `StepUpChallenge`, `StepUpAck`, `Tick` |
| `PrivilegedAction` (M5, existing code) | Action gated on step-up | (no durable state) | `Invoke(session)` → allowed/denied |

### 5.3 Abstract State

| Variable | Abstract Type | Why Needed | Bound | Explosion Risk |
|---|---|---|---|---|
| `cb_state` (M4) | `{Closed, Open, HalfOpen}` | the state that can wedge | 3 | low |
| `cb_probe_inflight` (M4) | BOOLEAN | the half-open invariant ("at most one") | 2 | low |
| `cb_failure_count` (M4) | 0..MAX_FAIL | thresholding | bounded | medium (cut to MAX_FAIL=2 for tractability) |
| `cb_calls_in_history` (M4) | bounded sequence of `{Success, Failure, ShortCircuit}` | for safety property phrasing | length ≤ 5 | medium (drop entirely if not needed for the prop) |
| `session_state` (M5) | `{Anon, Auth, StepReq, StepOk, Expired}` | the lifecycle that must not skip | 5 | low |
| `clock_tick` (M5) | 0..MAX_TICK | expiration ordering | bounded | medium (cut to MAX_TICK=3) |

### 5.4 Actions / Transitions

(M4 detailed in `specs/CircuitBreaker.tla`; M5 in `specs/SessionStepUp.tla`. Each verified-design doc lists every action.)

### 5.5 Safety Properties

**M4 (circuit breaker)**:
- `NoDoubleProbe`: `cb_state == HalfOpen ∧ cb_probe_inflight == TRUE ⇒` no other probe is started until the in-flight probe completes.
- `NoStuckHalfOpen`: every entry into `HalfOpen` eventually transitions to `Closed` or `Open` after the probe outcome.
- `NoSilentClose`: a transition `Open → Closed` requires an observable success event (no clock-only close).

**M5 (session step-up)**:
- `NoPrivWithoutStepUp`: invoking `PrivilegedAction` requires `session_state == StepOk`.
- `NoExpiredReuse`: `session_state == Expired ⇒` no further action accepted.
- `StepUpWindowEnforced`: `StepOk → Auth` happens after a configured window without privileged action.

### 5.6 Liveness / Progress Assumptions

**M4**: weak fairness on `Tick` — eventually the open-state timer expires and the breaker enters half-open. Weak fairness on `OnSuccess` — eventually a successful probe closes the breaker.

**M5**: weak fairness on `Tick` — eventually `StepOk` falls back to `Auth` after the window. Weak fairness on `Login` — eventually an authenticated user can begin a session.

### 5.7 Simplifications

| Simplification | Why It Still Catches Relevant Bugs |
|---|---|
| Single downstream per CircuitBreaker (no fan-out) | The half-open race is per-CB; symmetry argument covers fan-out |
| Boolean `probe_inflight` instead of in-flight set | Set arity > 1 is exactly what `NoDoubleProbe` forbids; reducing to boolean preserves the bug |
| Discrete clock ticks instead of timestamps | Timestamps are not load-bearing for the safety property |
| Session = single user (no multi-tenant) | Step-up window is per-session; multi-tenant is a symmetry argument |

---

## 6–8. Global Execution / Pre-Milestone / Post-Milestone Rules

Inherits §6–8 of the [v4 template](../templates/runbook-template_v_4_template.md). For this runbook, the baseline test commands are `cargo test --workspace` and (for M4 onward) the TLC dispatch via `~/.sldo/tla/tlc`.

---

## 9. Background Context

### Current State

SunLit ships fuzz harnesses (`cargo fuzz` per crate), property tests (proptest), CVE-regression tests (`cve_*`), miri (workspace), `timing_*` tests, and a `THREAT_MODEL.md` STRIDE analysis. There is one existing TLA+ spec (`specs/NativeDeviceTrust.tla` for the native-device-trust runbook). There is no Kani usage. There is no circuit-breaker module in `secure_resilience`.

### Problem

1. **Proof-grade evidence missing for safety-critical paths** — fuzz finds bugs probabilistically; for invariants that are "must hold for all inputs," exhaustive proofs at bounded sizes are stronger.
2. **No existing circuit-breaker** in `secure_resilience` — consumers building resilient services need this, and the new module is the natural place to demonstrate the TLA+-first design discipline.
3. **No protocol-level proof for session+step-up** — the existing `secure_identity` code is well-tested but the design has not been model-checked.
4. **No advisory CI lanes** for Kani or TLC — the proofs are valuable only if they run on every PR.

### Target Architecture

See §3 above. End state: 4 Kani harnesses + 2 TLC specs + 2 advisory CI lanes + a new `secure_resilience::circuit_breaker` module with rustdoc + dev-guide page.

### Key Design Principles

1. **Naive-then-Hardened TLA+** — every TLA+ spec ships with a Naive variant that fails TLC; only when the failure is observed do we switch to the Hardened design. This is the `/slo-tla` SKILL discipline.
2. **Bounded proofs** — Kani harnesses declare loop unwinds and input bounds explicitly. TLC bounds are stated in the verified-design doc.
3. **Advisory before blocking** — both CI lanes start advisory; promotion to blocking is gated on ≥1 green release cycle (research recommendation).
4. **OSS docs are first-class output** — every milestone produces rustdoc with examples on changed/new APIs, README updates if user-facing surface changes, a CHANGELOG entry, and dev-guide additions where new capability lands. M5 ships a dedicated `docs/dev-guide/formal-verification.md` describing what consumers can cite.
5. **Release notes describe what consumers gain** — "Kani-verified deny-by-default in secure_authz; TLA+-verified circuit breaker in secure_resilience" beats "added Kani harnesses to authz."
6. **Readability gate** — every TLA+ spec has a paired `.trace.md` translating any counterexample to a narrative; every Kani harness has a doc comment naming the invariant in plain English. If a future reader can't tell what a proof proves in 30 seconds, the proof is not done.
7. **Bus factor is real** — Apalache is volunteer-maintained per research; default to TLC and only reach for Apalache on explosion. Kani is AWS-backed but its Rust-feature coverage moves; pin a known-good Kani version in CI.

### What to Keep

- Existing `secure_resilience::{IntegrityCheck, RaspEngine, EnvironmentSignal, ...}` API.
- Existing `secure_identity::{session, step_up}` API.
- `specs/NativeDeviceTrust.*` — out of scope, untouched.
- All existing CI workflows.
- All existing test suites (proptest, cargo-fuzz, miri, timing).

### What to Change

- **`crates/<crate>/proofs/`** — new directory per Kani-using crate; harness `.rs` files inside.
- **`crates/secure_resilience/src/circuit_breaker.rs`** — NEW (M4): closed/open/half-open state machine, single-probe rule, configurable thresholds, observability hooks.
- **`crates/secure_resilience/src/lib.rs`** — declare the new module; re-export public types.
- **`crates/secure_resilience/Cargo.toml`** — possibly add `tracing` dep (already in workspace) for observability hooks; no other new deps.
- **`specs/CircuitBreaker.tla`** + `.cfg` + `.trace.md` (NEW, M4).
- **`specs/SessionStepUp.tla`** + `.cfg` + `.trace.md` (NEW, M5).
- **`docs/slo/design/circuit-breaker-verified.md`** (NEW, M4); **`docs/slo/design/session-step-up-verified.md`** (NEW, M5).
- **`.github/workflows/kani.yml`** (NEW, M1; extended M2/M3); **`.github/workflows/tla.yml`** (NEW, M5).
- **`docs/dev-guide/formal-verification.md`** (NEW, M5).
- **`docs/dev-guide/secure-resilience.md`** — add circuit-breaker section (M4).
- **`README.md`** — Adversarial-testing section gains a "Formal verification status" line; Crates table for `secure_resilience` mentions circuit-breaker.
- **`CHANGELOG.md`** — entry per milestone.

### Global Red Lines

Inherits §9 of v4. Plus:

- No Kani harness that proves a vacuously-true property (per `/slo-tla` SKILL anti-pattern: "the safety property holds even when you comment out the fix").
- No TLA+ spec without a Naive variant that fails — every TLC pass must be earned.
- No "verification theatre" — every proof encodes a real invariant whose violation would be a CVE-class bug.
- No silent promotion of advisory CI to blocking — promotion is a separate runbook.
- No TLC `-workers auto` before cutting an over-concrete model.

---

## 10. Carry-forward from prior retros

(Empty at authoring time.)

---

## 11–14. BDD / Dependency / Evidence / Self-Review

Inherits §11–14 of v4. Self-Review additions for this runbook:
- Did every TLA+ spec earn its TLC pass with a Naive variant that fails first?
- Did every Kani harness state its invariant in plain English in a doc comment?
- Did the CI lane runtime stay within its declared cap?

---

## 15–16. Lessons / Completion Templates

Standard v4 templates. Lessons → `docs/slo/lessons/fv-m<N>.md`; completion → `docs/slo/completion/fv-m<N>.md`.

---

## 17. Milestone Plan

### Milestone 1 — Kani toolchain bootstrap + first proof + advisory CI lane

**Goal**: Land Kani in the workspace with a single end-to-end working proof (`secure_data` non-zero nonce, the narrowest of the four because AEAD is axiomatised). Pin Kani version. Add advisory CI lane with 15-min runtime cap.

**Carmack-style reliability goal**: Static analysis is mandatory (the new lane *is* the static analysis); make invalid states unrepresentable (the proof proves a state-shape invariant).

**Important design rule**: Pick the simplest proof that exercises the full pipeline. Subsequent proofs reuse the harness convention.

**Refactor budget**: `Minimal local refactor permitted in listed files only`.

#### Contract Block

| Field | Value |
|---|---|
| Files allowed to change | `crates/secure_data/proofs/` (NEW dir; `nonce_non_zero.rs`), `crates/secure_data/Cargo.toml` (gate proofs with `[features] kani = []` if needed; **no new runtime deps**), `.github/workflows/kani.yml` (NEW), `docs/dev-guide/formal-verification.md` (NEW skeleton — extended in M5), `CHANGELOG.md`, `README.md` (Adversarial-testing section gains a line) |
| New dependencies allowed | `kani-verifier` (dev / via toolchain — installed by CI step `cargo install --locked kani-verifier`, version pinned). No runtime deps added. |
| Migration allowed | `no` |
| Compatibility commitments | All existing tests remain green. All existing CI lanes remain green. The new lane is advisory (workflow-level `continue-on-error: true` or marked non-required). |
| Resource bounds | CI lane runtime hard cap = 15 minutes per research; the lane fails the job (advisory) if exceeded. Kani input bounds: nonce byte length = 12 (AES-GCM standard), unwind = 1 (no loops in nonce construction). |
| Invariants/assertions required | (1) Kani proves: for the v1 AEAD path, the nonce array returned by the encrypt entry path satisfies `nonce != [0u8; 12]`. (2) The harness fails (Kani reports a counterexample) if the implementation is changed to return all-zero nonces. |
| Debugger expectation | Kani's `--visualize` produces an HTML trace that a future reviewer can read in <60 seconds. |
| Static analysis gates | `cargo fmt`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo audit && cargo deny check && cargo vet`, plus the new `cargo kani` step. |
| Forbidden shortcuts | No "TODO: real proof in M2." No vacuous proof. No commented-out harness. No silently disabling CI lane. |
| Data classification | `Public` (proofs are open-source artifacts). |
| Proactive controls in play | `C2` (Leverage Security Frameworks — Kani as a verifier), `C9` (Implement Security Logging — CI lane outputs are evidence). |
| Abuse acceptance scenarios | `tm-fv-abuse-1`: a future contributor changes the nonce code to all-zeros (deliberately or accidentally) → Kani CI fails the lane and reports the counterexample. |

#### Out of Scope / Must Not Do

- Any other Kani proof (M2/M3).
- Any TLA+ work (M4/M5).
- Promoting Kani lane to blocking (post-runbook).

#### Step-by-Step

1. Read research synthesis.
2. Write the Kani harness `crates/secure_data/proofs/nonce_non_zero.rs` first; expect TLC—wait, expect Kani to fail (no impl yet, OR if impl exists already, the harness is the test).
3. Confirm the harness fails when nonce is set to zero (introduce a temporary "broken" branch behind a `cfg(kani)` flag if needed; remove before commit).
4. Wire `cargo kani` lane in `.github/workflows/kani.yml` (advisory, 15-min cap).
5. Document: dev-guide skeleton + rustdoc on the harness.
6. Update CHANGELOG and README.
7. Run formatter, lint, tests, audit.
8. Smoke: PR-time CI run shows the new lane green.

#### BDD Acceptance Scenarios

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| Kani proves non-zero nonce on current code | happy path | current `secure_data` impl | run `cargo kani -p secure_data --harness nonce_non_zero` | succeeds; report shows `assertion holds` |
| Kani fails on broken impl | abuse case (`tm-fv-abuse-1`) | impl mutated to return `[0u8; 12]` | run `cargo kani` | reports counterexample; assertion fails |
| CI lane runtime within cap | resource bound | CI run on PR | check workflow timing | < 15 minutes |
| Workspace tests still green | compatibility | all existing tests | `cargo test --workspace` | green |
| Lane is advisory | dependency failure | Kani lane fails | merge gate | merge not blocked (continue-on-error) |

(Files Allowed To Change, Regression Tests, Compatibility Checklist, E2E Runtime, Smoke Tests, Evidence Log, Definition of Done, Post-Flight per v4 template.)

---

### Milestone 2 — Kani proofs for `secure_authz` deny-by-default + `secure_boundary` depth/size/field limits

**Goal**: Two production-grade Kani proofs land. Both are listed green-flag in research.

**Important design rule**: Each proof's harness lives in `crates/<crate>/proofs/<invariant>.rs`. Each harness has a doc comment in plain English describing the invariant. Bounded inputs are stated in the harness (`#[kani::unwind(...)]`, `kani::any()` with bounds).

**Refactor budget**: `Minimal local refactor permitted in listed files only`.

#### Contract Block (highlights)

| Field | Value |
|---|---|
| Files allowed to change | `crates/secure_authz/proofs/deny_by_default.rs` (NEW), `crates/secure_boundary/proofs/{depth_limit.rs,size_limit.rs,field_count_limit.rs}` (NEW), `.github/workflows/kani.yml` (extend matrix to include 4 harnesses), `docs/dev-guide/formal-verification.md`, `CHANGELOG.md` |
| New dependencies allowed | `none` |
| Resource bounds | Per-harness runtime cap inside the 15-min lane budget. Kani input bounds: policy-set size ≤ 4 (authz); nesting depth ≤ 12; field count ≤ 16; body size ≤ 2KB (boundary). |
| Invariants/assertions required | (1) `Authorizer::authorize(s,a,r)` returns `Decision::Deny{reason}` when no policy matches. (2) `SecureJson<T>` rejects depth > limit. (3) `SecureJson<T>` rejects field count > limit. (4) `SecureJson<T>` rejects body size > limit. |
| Forbidden shortcuts | No "small bound" proof that lets an attacker provoke the unbounded case. State the bound in the doc; document why it covers the real input space. |
| Data classification | `Public` |
| Proactive controls in play | `C5 secure_boundary::SecureJson` (Validate All Inputs), `C7 secure_authz::Authorizer` (Enforce Access Controls), `C2` (Frameworks/Libraries — Kani). |
| Abuse acceptance scenarios | `tm-fv-abuse-2`: contributor introduces a fall-through that returns `Allow` on no-match → Kani catches. `tm-fv-abuse-3`: contributor raises a limit silently → Kani catches via the bound mismatch. |

(BDD scenarios per harness; Evidence Log; DoD per v4.)

---

### Milestone 3 — Kani proofs for `secure_data` nonce-uniqueness within path + `secure_errors` public-body-no-leak

**Goal**: The two remaining Kani proofs.

**Carmack-style reliability goal**: Make invalid states unrepresentable — the proof of "no internal-detail leak" forces the public-body shape to be derivable from the error variant alone, never from `Display`/`Debug` text.

**Refactor budget**: `Minimal local refactor permitted in listed files only`.

#### Contract Block (highlights)

| Field | Value |
|---|---|
| Files allowed to change | `crates/secure_data/proofs/nonce_unique_within_path.rs` (NEW), `crates/secure_errors/proofs/no_internal_detail_in_response.rs` (NEW), `.github/workflows/kani.yml` (extend matrix), `docs/dev-guide/formal-verification.md`, `CHANGELOG.md` |
| New dependencies allowed | `none` |
| Resource bounds | Kani inputs: 2 nonces in a single call path; `AppError` variant set bounded to the existing public enum |
| Invariants/assertions required | (1) Within a single `encrypt_for_storage` call the two nonces (if any) are distinct (per AEAD safety; AEAD itself axiomatised). (2) For all `AppError` variants `e`, `into_response_parts(&e)` does not include `e.to_string()` or any `dep:` field in the public body. |
| Abuse acceptance scenarios | `tm-fv-abuse-4`: contributor changes `into_response_parts` to embed `format!("{}", err)` → Kani catches. |
| Data classification | `Public` |
| Proactive controls in play | `C2`, `C8 secure_data::envelope` (Protect Data Everywhere — including via nonce uniqueness), `C10 secure_errors::http` (Handle All Errors and Exceptions). |

---

### Milestone 4 — Add `secure_resilience::circuit_breaker` module + TLA+ spec + verified-design doc

**Goal**: Ship a new circuit-breaker module in `secure_resilience` whose design is TLA+-verified before the implementation lands. The spec proves no-double-probe, no-stuck-half-open, no-silent-close. The Naive variant fails TLC; the Hardened variant passes.

**Carmack-style reliability goal**: Bounded resources (failure-count threshold, open-state timer, single-probe boolean — all explicit); make invalid states unrepresentable (state machine encoded as Rust enum, not a string); assertions on transition preconditions; observability hooks (no silent state change).

**Important design rule**: Write the Naive spec FIRST. Confirm TLC finds the half-open-double-probe race. Then write the Hardened spec with the single-probe rule and confirm TLC is green at the declared bound. Then implement Rust to match the Hardened design. Per `/slo-tla` SKILL — "TLA+ is not the right tool" output is acceptable if the suitability gate rejects, but the half-open race is a textbook concurrency race so this is in scope.

**Refactor budget**: `Targeted refactor permitted for adding the new module to secure_resilience`.

#### Contract Block

| Field | Value |
|---|---|
| Inputs | `CircuitBreaker::call(fn closure)` callers; `CircuitBreakerPolicy` configuration (failure threshold, open-state duration); optional `CircuitBreakerObserver` for hooks |
| Outputs | New public types: `CircuitBreaker`, `CircuitBreakerPolicy`, `CircuitBreakerObserver`, `CircuitBreakerError`, `CircuitBreakerState`. New TLA+ spec + verified-design doc. |
| Interfaces touched | `secure_resilience::circuit_breaker` (NEW module); `secure_resilience::lib` (re-export only) |
| Files allowed to change | `crates/secure_resilience/src/circuit_breaker.rs` (NEW), `crates/secure_resilience/src/lib.rs` (declaration + re-exports), `crates/secure_resilience/tests/fv_m4_circuit_breaker.rs` (NEW: BDD), `crates/secure_resilience/Cargo.toml` (only if `tracing` dep is missing — already in workspace, so likely no change), `specs/CircuitBreaker.tla` (NEW), `specs/CircuitBreaker.cfg` (NEW), `specs/CircuitBreakerNaive.cfg` (NEW), `specs/CircuitBreaker.trace.md` (NEW), `docs/slo/design/circuit-breaker-verified.md` (NEW), `docs/dev-guide/secure-resilience.md` (extend with circuit-breaker section), `docs/dev-guide/formal-verification.md` (extend with circuit-breaker example), `CHANGELOG.md`, `README.md` (Crates table for `secure_resilience` mentions circuit-breaker; ARCHITECTURE.md gets the new component) |
| Files to read before changing anything | M3 lessons; [`docs/slo/research/formal-verification-kani-tla/synthesis.md`](../research/formal-verification-kani-tla/synthesis.md); existing `crates/secure_resilience/src/{lib,rasp,integrity,environment,error}.rs`; `specs/NativeDeviceTrust.tla` for project TLA+ conventions |
| New files allowed | All listed under "Files allowed to change" with NEW marker |
| New dependencies allowed | `none` (use existing workspace deps only) |
| Migration allowed | `no` |
| Compatibility commitments | All existing `secure_resilience` types unchanged. All M1–M3 Kani lanes remain green. No public-API rename. |
| Resource bounds introduced/changed | `CircuitBreakerPolicy::failure_threshold` (default 5, configurable), `CircuitBreakerPolicy::open_duration` (default 30s, configurable), `probe_inflight: AtomicBool` (single-probe rule). All bounded; encoded as `const` defaults + builder methods. |
| Invariants/assertions required | (1) `state == HalfOpen ∧ probe_inflight == true ⇒` next `Call` returns `CircuitBreakerError::ProbeInFlight` (no double probe). (2) `state == Open` returns immediately with `CircuitBreakerError::CircuitOpen` (short-circuit). (3) Transition `Open → Closed` is impossible without an observable success. (4) Tracing event emitted on every state transition. |
| Debugger / inspection expectation | TLC trace files under `specs/CircuitBreaker.trace.md` document the Naive counterexample in narrative form. Rust test exercises every state transition under `--nocapture`. |
| Static analysis gates | `cargo fmt`, `cargo clippy -p secure_resilience --all-targets --all-features -- -D warnings`, `cargo audit && cargo deny check && cargo vet`, **TLC at declared bound** for both Naive (must fail) and Hardened (must pass). |
| Forbidden shortcuts | No skipping the Naive variant. No model that doesn't actually exhibit the race in Naive form. No `unwrap()` in production paths. No silent state changes. No `unsafe`. |
| Data classification | `Internal` (the module is public API; the proof artifacts are open-source). |
| Proactive controls in play | `C5` (Validate All Inputs — including the Closure's outcome), `C10 secure_resilience::circuit_breaker` (Handle All Errors and Exceptions). |
| Abuse acceptance scenarios | `tm-fv-abuse-5`: a malicious or buggy downstream returns failures fast → circuit breaker opens within `failure_threshold` calls; subsequent calls short-circuit; consumers do not stampede. `tm-fv-abuse-6`: contributor removes the `probe_inflight` check → TLC fails; PR cannot pass advisory lane. |

#### Out of Scope / Must Not Do

- Async-aware circuit breaker (sync-first; async wrapper is a follow-up).
- Per-request weighting / sliding-window thresholds (post-1.0).
- Distributed circuit-breaker state (single-process; out of scope by design).

#### Step-by-Step

1. Read research synthesis; review `specs/NativeDeviceTrust.tla` for project TLA+ conventions.
2. Write `specs/CircuitBreakerNaive.cfg` and the spec body that omits the `probe_inflight` constraint.
3. Run TLC; confirm it finds the double-probe trace; document narratively in `specs/CircuitBreaker.trace.md`.
4. Write `specs/CircuitBreaker.cfg` (Hardened) + spec body with the single-probe rule.
5. Run TLC; confirm green at declared bound (3 actors, 5 calls, 2 failure injections).
6. Write `docs/slo/design/circuit-breaker-verified.md` with the Naive counterexample, the fix, the bounds.
7. Write Rust BDD test stubs (`crates/secure_resilience/tests/fv_m4_circuit_breaker.rs`).
8. Implement `circuit_breaker.rs` mirroring the Hardened design.
9. Make BDD scenarios pass (including the double-probe rejection scenario).
10. Run formatter, lint, full tests, audit, both TLC variants (one fails, one passes).
11. Write rustdoc with worked example, dev-guide section, CHANGELOG entry, README + ARCHITECTURE updates.
12. Smoke + Self-Review.

#### BDD Acceptance Scenarios

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| closed-state success path | happy path | breaker in `Closed` | call returns Ok | breaker stays Closed; failure_count resets |
| failure threshold opens | dependency failure | breaker in `Closed`, threshold=2 | two consecutive call failures | breaker → `Open`; subsequent call short-circuits with `CircuitOpen` |
| open-duration elapses → half-open | retry behaviour | breaker `Open`, duration elapsed | next call after timer | breaker → `HalfOpen`; one probe permitted |
| half-open double-probe rejected | concurrency / abuse case (`tm-fv-abuse-6`) | breaker `HalfOpen`, probe in flight | second call attempted | returns `ProbeInFlight`; no second probe started |
| probe success closes | happy path | breaker `HalfOpen`, probe Ok | probe completes | breaker → `Closed`; observer notified |
| probe failure re-opens | partial failure | breaker `HalfOpen`, probe Err | probe completes | breaker → `Open`; timer resets |
| observer hook fires on every transition | resource bound / observability | breaker with observer | any transition | observer.on_transition called exactly once per transition |
| TLC Naive variant fails | proof-grade | naive spec | run TLC | reports double-probe counterexample (narrative in trace.md) |
| TLC Hardened variant passes | proof-grade | hardened spec | run TLC at declared bound | green; no invariants violated |

(Regression tests, Compatibility checklist, E2E runtime, Smoke tests, Evidence Log, DoD per v4 template — each Evidence Log row includes both the Rust commands and the TLC commands.)

#### Documentation requirements (M4-specific)

- rustdoc with at least one runnable example for `CircuitBreaker::call` (the canonical use).
- `docs/dev-guide/secure-resilience.md`: new "Circuit breaker" section with worked example.
- `docs/dev-guide/formal-verification.md`: extended with the Naive→Hardened narrative as a worked case study.
- `CHANGELOG.md`: "secure_resilience now ships a TLA+-verified circuit breaker (closed/open/half-open with single-probe rule). Configurable thresholds; observability via `CircuitBreakerObserver`."
- `README.md`: Crates table row for `secure_resilience` updated to include circuit breaker; the "Adversarial testing" section gains a "TLA+: circuit breaker" mention.

---

### Milestone 5 — TLA+ spec for `secure_identity` session+step-up + verified-design doc + `tla.yml` CI lane

**Goal**: TLA+-verify the design of the existing `secure_identity` session+step-up flow. The proof states: no privileged action reachable from unauthenticated state; expired sessions never reusable; step-up window is correctly enforced. Land the `tla.yml` advisory CI lane (10-min cap) covering both M4 and M5 specs.

**Carmack-style reliability goal**: Static analysis as a CI lane (the new TLA+ lane); make invalid states unrepresentable (the existing Rust code already encodes the state machine; TLA+ proves the design respects the safety properties); debugger expectation (TLC trace files document any future regression).

**Important design rule**: M5's TLA+ work is *retrospective* — it model-checks an existing implementation. The Naive variant intentionally drops the step-up gate; TLC must find a privileged-action-without-step-up trace. Then the Hardened spec restores the gate; TLC must be green.

**Refactor budget**: `No refactor permitted beyond direct implementation of the spec + CI + docs`.

#### Contract Block

| Field | Value |
|---|---|
| Files allowed to change | `specs/SessionStepUp.tla` (NEW), `specs/SessionStepUp.cfg` (NEW), `specs/SessionStepUpNaive.cfg` (NEW), `specs/SessionStepUp.trace.md` (NEW), `docs/slo/design/session-step-up-verified.md` (NEW), `docs/dev-guide/formal-verification.md` (final form), `docs/dev-guide/secure-identity.md` (extend with formal-verification note), `.github/workflows/tla.yml` (NEW: covers both `CircuitBreaker.tla` and `SessionStepUp.tla`), `CHANGELOG.md`, `README.md` (Adversarial-testing section gains "TLA+: session+step-up") |
| New dependencies allowed | `setup-java` action in CI workflow only (no Rust deps). |
| Migration allowed | `no` |
| Compatibility commitments | All existing `secure_identity` tests remain green. All M1–M4 lanes remain green. No source-code change in `secure_identity` (M5 is spec + docs + CI only). |
| Resource bounds | TLC bound: 2 sessions, 3 actions, 2 expirations. CI lane runtime cap = 10 min per research. |
| Invariants/assertions required | (1) `NoPrivWithoutStepUp` holds at TLC bound. (2) `NoExpiredReuse` holds at TLC bound. (3) `StepUpWindowEnforced` holds at TLC bound. |
| Static analysis gates | TLC at declared bound (Naive must fail; Hardened must pass). All existing static-analysis gates. |
| Forbidden shortcuts | No skipping the Naive variant. No bound where the Naive case passes silently. No "verification theatre." |
| Data classification | `Public` |
| Proactive controls in play | `C6 secure_identity::session` (Implement Digital Identity), `C7 secure_identity::step_up` (Enforce Access Controls). |
| Abuse acceptance scenarios | `tm-fv-abuse-7`: a future change skips the step-up gate → TLC fails the lane. `tm-fv-abuse-8`: a future change extends the step-up window beyond policy → TLC fails the lane. |

(BDD: Naive fails / Hardened passes / `tla.yml` runs both M4 and M5; Evidence Log; DoD per v4.)

#### Documentation requirements (M5-specific)

- `docs/dev-guide/formal-verification.md` reaches its final shape (covers all 4 Kani harnesses + 2 TLA+ specs; describes what consumers can cite; describes promotion-to-blocking criteria for a follow-up runbook).
- `docs/dev-guide/secure-identity.md` adds a "Formal verification" subsection with a one-paragraph summary and a link to the verified-design doc.
- `CHANGELOG.md`: "secure_identity session+step-up flow is now TLA+-verified at declared bounds (2 sessions, 3 actions, 2 expirations). The `tla.yml` CI lane runs both circuit-breaker and session+step-up specs on every PR (advisory)."
- `README.md`: Adversarial-testing section's "Formal verification" line becomes complete (Kani: 4 proofs across 4 crates; TLA+: 2 specs with TLC at stated bounds, advisory CI).
- `ARCHITECTURE.md`: brief note that `secure_identity` design is TLA+-verified.

---

## 18. Documentation Update Table

| Milestone | ARCHITECTURE.md Update | README.md Update | .gitignore Update | Other Docs |
|---|---|---|---|---|
| 1 | Note: Kani toolchain present | Adversarial-testing line: "Kani: 1 proof (advisory CI)" | TLC-style ignores from `/slo-tla` SKILL §5 | `docs/dev-guide/formal-verification.md` (NEW skeleton) |
| 2 | (no change) | Adversarial-testing line updated to "Kani: 3 proofs" | — | dev-guide extended; CHANGELOG |
| 3 | (no change) | "Kani: 4 proofs across `secure_authz`, `secure_boundary`, `secure_data`, `secure_errors`" | — | dev-guide; CHANGELOG |
| 4 | New `secure_resilience::circuit_breaker` component | Crates table updated; "TLA+: circuit breaker" added | TLC artifacts under `specs/states/` etc. | `docs/dev-guide/secure-resilience.md`, `docs/slo/design/circuit-breaker-verified.md`, dev-guide; CHANGELOG |
| 5 | Note: `secure_identity` design TLA+-verified | "TLA+: 2 specs (circuit-breaker, session+step-up); advisory CI" | — | `docs/slo/design/session-step-up-verified.md`, `docs/dev-guide/secure-identity.md`, dev-guide complete; CHANGELOG |

---

## 19. Optional Fast-Fail Review Prompt for Agents

> Restate the milestone goal, allowed files, forbidden changes, compatibility, dependencies, required tests + proofs (Kani harnesses or TLA+ specs), resource bounds, invariants, static-analysis gates (including TLC for M4/M5), debugger expectation, and Definition of Done. Cite the research synthesis row for every tooling choice and the verified-design doc for every TLA+ bound.

---

## 20. Source Basis

This runbook is a v4 instance authored against [`docs/slo/templates/runbook-template_v_4_template.md`](../templates/runbook-template_v_4_template.md). Research basis: [`docs/slo/research/formal-verification-kani-tla/dossier.md`](../research/formal-verification-kani-tla/dossier.md) (40 sources, `incomplete:false`; verdicts: 3/4 Kani proofs green, 1 yellow with axiomatised AEAD; TLC default; Apalache reserved; 15-min Kani cap, 10-min TLC cap, advisory until ≥1 release cycle). Idea basis: [`docs/slo/idea/formal-verification-kani-tla.md`](../idea/formal-verification-kani-tla.md). M4 scope (circuit-breaker module add + TLA+) was confirmed with the user; the existing `secure_resilience` crate has no circuit breaker today.
