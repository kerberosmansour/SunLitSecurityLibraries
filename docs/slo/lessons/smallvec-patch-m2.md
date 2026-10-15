---
filed_issues: []
---

# Lessons Learned — SmallVec patch Milestone 2

## What changed
- Admitted SmallVec 1.15.2 in the workspace and isolated HMAC consumer locks, with no manifest or dependency-identity change.
- Recorded a narrow `safe-to-deploy` cargo-vet delta after reviewing the immutable archives, source delta, publisher history, build authority and changed ownership paths.
- Added durable SLO verification for the reproduced zero-inline `DrainFilter::keep_rest` defect and for the candidate's initialization, conversion, spill/unspill, alignment, zero-sized and destructor paths.

## Results vs thesis
- N/A — this is dependency assurance, not a value-bearing product milestone. The predicted graph-only patch was preserved and the affected ownership path changed from a Kani counterexample on 1.15.1 to a bounded pass on 1.15.2.

## Outcome vs promise
- N/A — this maintenance milestone adds no public capability. Default and all-feature workspace suites, isolated HMAC consumer scenarios, documentation and native-boundary checks show that the maintained outcomes remain available.

## Design decisions and why
- Keep the update lock-only — the workspace already permits the compatible 1.15 release line, and the candidate adds no dependency or feature requirement.
- Treat the Kani result as bounded evidence — it establishes the named paths and bounds, not whole-crate memory safety.
- Keep `drain_keep_rest` and `debugger_visualizer` disabled — neither optional feature is needed by the product, and the published crate omits the Natvis file referenced by the latter.
- Record the delta audit only after source, provenance, native and formal review — cargo-vet evidence must describe work actually performed.

## Mistakes made
- The first initialization proof used an unwind bound that was too low for a built-in comparison; it was rerun at bound 20 and only the completed result was accepted.
- The exact union keep-rest proof was allowed to consume roughly 7 GiB before it was stopped; that attempt produced no verdict and is explicitly unverified.
- The HMAC inventory script was initially invoked without its required `--output` argument; the correct self-test and admission invocations subsequently passed.

## Root causes
- Proof unwind bounds must cover library and compiler-generated paths as well as the visible harness.
- The union representation expands the exact symbolic keep-rest state beyond the practical local resource budget.
- The inventory CLI requires a durable JSON destination even when used as a check.

## What was harder than expected
- Separating a genuine ownership repair from unrelated upstream performance language required reviewing the published archives, the source commits and both constructor paths.
- The complete workspace/all-feature suite is broad and includes optional provider integrations, so validation took materially longer than the lock diff suggests.

## Naming conventions established
- Dependency-only runbooks use `RUNBOOK-<crate>-patch.md`, with matching `<crate>-patch-m<N>.md` verification, lessons and completion records.
- Formal rows name the representation, exact harness, unwind bound, check count and unreachable count.

## Test patterns that worked well
- A red/green proof using an identical harness against old and new immutable sources isolated the semantic repair.
- Script-disabled lock resolution plus a combined official OSV scan covered every root and nested toolchain lock before any dependency code was built.
- Native enum/union tests and small arbitrary Kani transition kernels complemented the exact counterexample without overstating coverage.

## Missing tests that should exist now
- A bounded exact union keep-rest proof remains desirable if a future solver/toolchain can complete it within an agreed resource budget.
- Miri coverage would add an independent dynamic check when the repository admits a pinned, scanned Miri toolchain.
- Upstream should package or remove the missing Natvis reference before this workspace considers `debugger_visualizer`.

## Rules for the next milestone
- Scan every resolved candidate lock and review the complete graph diff before compiling any newly admitted dependency code.
- Set explicit time and memory budgets for each formal harness and record interrupted runs as unverified.
- Separate correctness evidence from compiler-performance claims when upstream changes have distinct const and runtime paths.
- Do not enable an optional dependency feature until its published artifact is independently checked for completeness.

## Template improvements suggested
- Add first-class fields for proof resource budgets and interrupted/unverified results.
- Let dependency-maintenance runbooks distinguish local milestone completion from the PR-only required-check gate.

## Issue filing disposition
- The missing Natvis artifact is classified `upstream-OSS`. No external issue was filed because this maintenance authorization did not explicitly authorize messaging the upstream project; the finding remains in the runbook ledger for a maintainer-led contact.
