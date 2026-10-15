# SmallVec 1.15.2 patch runbook

## Milestone tracker

| Milestone | Title | Status | Notes |
|---|---|---|---|
| M1 | Admission and source review | done | Exact two-lock delta; official OSV scan and full source/provenance review passed. |
| M2 | Runtime, formal and repository validation | done | Completed 2026-10-15; [verification](../verify/smallvec-patch-kani.md), [lessons](../lessons/smallvec-patch-m2.md), [completion](../completion/smallvec-patch-m2.md). GitHub checks remain the merge gate. |

## Carry-forward from prior retros

None. This bounded maintenance runbook was opened for the SmallVec patch only.

## M2 contract

### Goal

Admit SmallVec 1.15.2 without widening the dependency graph, and verify the
changed ownership/storage paths in the exact workspace and isolated HMAC
consumer graphs.

### Exact file allow-list

- `Cargo.lock`
- `fixtures/jwt-hmac-consumer/Cargo.lock`
- `supply-chain/audits.toml`
- `CHANGELOG.md`
- `docs/slo/current/RUNBOOK-smallvec-patch.md`
- `docs/slo/verify/smallvec-patch-kani.md`
- `docs/slo/lessons/smallvec-patch-m2.md`
- `docs/slo/completion/smallvec-patch-m2.md`

Private proof crates and raw evidence are outside the repository. No manifest,
public API, production source, tool pin or release version may change.

### BDD acceptance scenarios

| ID | Scenario | Required result |
|---|---|---|
| BDD-1 | Resolve the candidate with lifecycle/build execution disabled and scan every candidate lock. | Exact SmallVec-only substitutions; official pinned OSV succeeds with zero malicious advisories. |
| BDD-2 | Partially consume `DrainFilter` for a zero-inline `SmallVec<[Box<u8>; 0]>`, then keep the rest. | 1.15.1 produces a semantic memory counterexample; 1.15.2 preserves `[1,3,5,6,7,8]`. |
| BDD-3 | Initialize, convert from inline/heap vectors, spill and unspill capacity 0/1/N values. | Order, length, capacity and allocation ownership are preserved in enum and union representations. |
| BDD-4 | Exercise aligned, zero-sized and destructor-bearing values. | Alignment/order hold and each destructor runs exactly once. |
| BDD-5 | Validate the maintained repository and isolated HMAC consumer. | Formatting, lint, tests, docs, native boundary, no-RSA, cargo-vet and fresh OSV gates pass. |

### Compatibility and exclusions

- Current enabled SmallVec features remain `const_generics`, `const_new`,
  `default`, `serde` and `union`.
- `drain_keep_rest` and `debugger_visualizer` remain disabled in production.
- Bounded Kani evidence is not a whole-crate proof, Miri result, compiler
  performance result or physical deployment qualification.
- No public crate version or registry publication is required for lock-only
  transitive maintenance.

### Evidence log

| Evidence | Actual result |
|---|---|
| Repository hygiene | Dedicated branch `review/smallvec-patch-1-15-2` from Rust main `2bc3ab91ee170fc4cd93b2a08864a28ee9a27930`; only allow-listed repository files change. |
| Admission | Official checksum-verified OSV 2.7.0 passes the combined seven-lock/1,643-occurrence graph and both isolated two-package proof locks. The final root scan contains the three unchanged, exact, owned exceptions for `rsa` 0.9.10, `smartstring` 1.0.1 and `xxhash-rust` 0.8.15, all expiring 2026-11-14; it contains no `MAL-*` advisory. |
| Provenance | Immutable crates.io archives and source commits reviewed; publisher changed from `mbrubeck` to `emilio`; no dependency, build script or ambient-authority addition. |
| Red/green defect | Kani 0.68: 1.15.1 fails with an assertion and deallocated-object read; identical 1.15.2 harness passes 930 checks with zero failures. |
| Candidate transitions | Native enum/union tests pass; Kani initialization/from-vec bound 20 and arbitrary spill/unspill bound 12 pass for enum and union. |
| Audit | Genuine AI-assisted `safe-to-deploy` delta recorded with explicit optional-feature and whole-proof limits; offline cargo-vet succeeds. |
| Full repository/platform | Format, clippy, default/all-feature workspace tests, doctests, warning-denied docs, native dependency guards, isolated HMAC/no-RSA tests, 52 maintenance/script tests, fresh seven-lock OSV and offline cargo-vet pass. GitHub required checks remain the merge gate. |

### Detected work ledger

| Finding | Disposition | Rationale / owner |
|---|---|---|
| Upstream package omits the Natvis file referenced by `debugger_visualizer`. | upstream_feedback | Excluded feature; record for a future upstream maintenance contact by repository maintainers. |
| `new_const` uses a separate path, so the upstream compiler-workaround claim is not established for const construction. | accepted_risk | Current source behavior remains valid; performance/codegen claim is excluded and should be revisited on the next SmallVec update. |
| Exact union keep-rest proof exhausted roughly 7 GiB before completion. | accepted_risk | Stopped as unverified; native union regression plus completed union spill/unspill proof cover the admitted representation, and production does not enable `drain_keep_rest`. |
| Miri is unavailable in the admitted toolchain. | accepted_risk | No tool was installed ad hoc; Kani red/green and native candidate evidence are retained, with Miri explicitly unclaimed. |

### Definition of done

- Every BDD row has current evidence.
- The genuine delta audit and exact locks are the only dependency-maintenance changes.
- Full repository, isolated consumer, cargo-vet and fresh OSV checks pass.
- GitHub required checks pass for the exact reviewed commit before merge.
- Verification, lessons and completion records state all limits.

### Self-review gate

- Yes — every BDD scenario has current evidence.
- Yes — every changed repository file is on the exact allow-list.
- Yes — the audit describes the reviewed delta and does not fabricate coverage.
- Yes — interrupted formal work and optional-feature limitations are explicit.
- Yes — no dependency identity, manifest, public API, release version or production feature changed.
