# Completion Summary — JWT HMAC Profile Milestone 1

## Goal completed
Source milestone done. The explicit reduced profile uses bounded ring-backed
HMAC/JWT handling and a checked startup provider, with no rsa package in its
195-package isolated normal/build graph. Legacy defaults retain public-key/SSH
behavior. This feature is not in published 0.3.0; issue54 remains open for M2.

## Files changed
17 of the 18 confirmed paths changed. Root Cargo.lock remains unchanged. The
changes are manifest gates, lib/token/provider source, selected JWT tests,
standalone consumer manifest/lock/source, admission/proof helper, existing CI,
README/changelog/guide/threat-model and these three SLO artifacts. No other
source/tool recipe, external dependency identity, audit or advisory disposition changed.

## Tests added
Two real JWT/algorithm/key/claims tests and one private unsupported-key-utility test;
empty-cache graph, Windows exact-path inventory, ten malformed/mixed/duplicate/
post-summary proof parser cases, and two POSIX same-byte alias regressions.

## Runtime validations added
Six real separate consumer/startup processes: real JWT, own race, foreign first,
own first, competing registration and early upstream misuse. Actual mutation tests
fail both weakened policy assertions; both restored Kani kernels pass and all thirteen
covers are SATISFIED with automatic assertion reachability enabled and no stubs.

## Compatibility checks performed
Implementation78b3bc7: all required PR gates pass. CI38645105658 passed Linux,
macOS and Windows; default/optional/feature matrix, selected profile, workload,
package/docs/admission gates passed. Legacy all-feature workspace1395 tests,
workspace/selected/consumer Clippy and format passed. CodeQL and Semgrep are green.
OSV2.7.0 scanned all seven locks/1643 package occurrences before new builds.
External graph/source/checksum dictionaries unchanged; fixture exceptions never
inherit root dispositions. Independent review findings were reproduced/fixed;
the strict final parser accepts the actual retained red/green logs.

## Documentation updated
Unreleased README/changelog and migration/startup/bounds guide; abuse model,
inline proof scope, complete runbook evidence/self-review and lessons. Distinguish
legacy defaults, prior no-default asymmetric callers and additive feature limits.

## .gitignore changes
None. Generated reports/caches remain ignored; user-facing evidence is outside repo.

## Test artifact cleanup verified
No untracked test artifacts. Source mutations are restored; tracked diff stays
within the exact contract. Docs-only closeout follows verified implementation78b3bc7.

## Deferred follow-ups
User confirmation and M2 readiness, coordinated0.4.0 publication, packaged-consumer
and immutable registry/signature/SBOM verification. Issue54 is not closed early.

## Known non-blocking limitations
Bounds do not prove key entropy or erase vendor copies. Direct vendor parsing needs
caller bounds. Cargo feature unification can restore rsa; default full graphs retain
existing exact expiring public-key exceptions. Kani proves neither crypto nor
scheduling/foreign code; runtime scenarios cover selected interleavings only.

Evidence: https://github.com/kerberosmansour/SunLitSecurityLibraries/actions/runs/38645105658
