---
id: jwt-hmac-profile
prefix: jwt-hmac-profile
version: 4
stack: Rust
ai_component: false
baseline: cargo test -p secure_identity --all-features --locked
---
# JWT HMAC-only profile and coordinated publication

Provide an explicit reduced `secure_identity` profile for applications that only
need internal HMAC JWTs. Preserve existing default public APIs and behavior by
moving their current asymmetric/SSH requirements into named default features.
Consumers select `default-features = false, features = ["jwt-hmac"]`; that isolated
normal consumer graph must contain no `rsa` Rust package. This does not claim that
all RSA machine code disappears from ring or that Cargo feature unification can
never re-enable RSA. JWT/JWKS/SSH/OIDC consumers retain an explicit compatible
asymmetric profile; existing expiring public-verification exceptions remain.

## Contract and compatibility

- Reuse admitted `ring` HMAC and jsonwebtoken11's public CryptoProvider/signature
  interfaces. Never implement a JWT parser, signature comparison or HMAC primitive.
  No new external package/version/source/checksum or verifier tool is authorized;
  root locks keep all known identities and audited graph elsewhere. New standalone
  fixture resolution must be an exact reviewed subset of that graph.
- Make direct SSH RSA/curve dependencies and jsonwebtoken/rust_crypto feature
  activation conditional; remove the unconditional dev-dependency crypto feature
  edge. Gate asymmetric JWT/JWKS/capability and SSH surfaces consistently while
  legacy defaults retain their behavior. Existing `jwks`/`oidc` features imply
  their required asymmetric group. No RSA support is silently available in the
  isolated reduced profile; mixed features must be documented honestly.
- HMAC provider factories support HS256/384/512 only, check symmetric key family
  and bounded key material, and return fixed typed errors for unsupported key/
  algorithm/JWK operations. No panic-producing unimplemented key utilities or
  ignored provider-installation failure. No secret-bearing Debug/log/error.
- Use a local std::sync::OnceLock initialization result before decoding in the
  reduced profile and expose a documented startup hook before consumer-side JWT
  encoding. Concurrent library callers reuse one result. A prior/conflicting
  foreign provider makes reduced-profile authentication unavailable, with no
  fallback or assumption about which provider is installed. A successful library
  installation cannot be replaced by a competing installer.
- Resource bounds for the new reduced profile: JWT input <=64 KiB; symmetric keys
  <=1024 bytes and at least 32/48/64 bytes for HS256/384/512 respectively. Reject
  out-of-bounds input with existing fixed errors before allocating crypto work.
  Preserve the legacy profile's existing claim/algorithm/key acceptance behavior.
- Validate signatures, expiry, issuer and audience using the existing vendor JWT
  validation boundary. Unsupported/asymmetric/none algorithms and wrong-key or
  tampered signatures fail closed. No claim validation is disabled.
- Source/docs/CI milestone only: record under Unreleased; no family version,
  crates.io publish, capability declaration or issue closure until a separate
  confirmed publication milestone. The published 0.3.0 mobile release remains
  immutable and its feature/source behavior must pass regressions.

Data: JWTs/configured HMAC keys Restricted; claims Confidential; synthetic test
material only. Proactive controls: validated input, safe error handling, existing
crypto/library reuse and data protection. Threat model: algorithm confusion,
provider initialization conflict/race, RSA reintroduction through feature
unification, graph drift and key/error exposure. Exemplars: jsonwebtoken11's
inspected public provider interfaces, existing token validator and admitted ring
HMAC. Anti-exemplars: stripping signatures/claim checks, insecure_decode, a global
provider install ignored on failure, feature-unified test graph presented as a
minimal consumer graph, fabricated audits or MAL exceptions.

## §5A Measurement / §5B operator and security contract

Maintainer owns the readout at M1 closure: isolated normal graph has zero rsa
packages; real JWT outcomes and provider startup cases pass; default/all-feature
regressions remain green; no external identity/checksum changes. No cloud account
or device is needed. Readiness: source and verified 0.3.0 baseline available;
existing source-verified Kani/tools are reusable after current graph admission.
No new tool download/install is permitted by this scope. If current tools/scanner
or provenance fail, stop the dependent verification rather than waive it.

Stage the standalone fixture lock so every root OSV workflow discovers it. Resolve
without builds/scripts, scan every root/tool/fixture lock, retain JSON/receipt and
full graph/provenance diff, then compile/test. Fixture exceptions never inherit
root exceptions. Read-only CI runs admission before the reduced-profile test.
Detected work ledger: every concrete finding must be fixed inside the allow-list
or explicitly routed; no silent file/scope extension. Existing advice cannot
justify changing source outside this list.

TLA suitability: false — reuse local std::OnceLock atomic initialization; no new
remote/concurrent protocol or custom synchronization algorithm. Isolated-process
startup and bounded race tests exercise its actual API interleavings. Kani:
required for pure algorithm/key-length/input-bound acceptance helpers at stated
bounds, using existing admitted tools; it does not prove vendor crypto, global
process scheduling or absence of SDK/internal key copies.

## §5C Outcome and BDD

oc-jwt-hmac-1 / cuj-jwt-hmac-1: a separate Rust consumer resolves the reduced graph,
initializes the HMAC-only provider, mints and authenticates a real internal HS256
JWT, and rejects forged/wrong-key/expired/wrong-issuer/wrong-audience/asymmetric
and malformed tokens; its normal dependency graph excludes rsa. Assertions span
manifest/lock -> production library/provider -> actual vendor signing/validation
-> authenticated identity/errors. No mock-only cryptography or graph proof.

BDD/red-first: before production changes, an isolated existing no-default-feature
consumer's graph still includes rsa; the graph assertion fails for that reason,
not a missing feature/compile error. Existing valid JWT behavior supplies baseline.
New factories/helper scenarios cover exact boundary lengths, unsupported families,
HS256/384/512 round trips and changed signatures. Separate subprocesses cover
concurrent own initialization, a foreign installation first, library first then
foreign attempt, and consumer encoding before initialization; library paths never
panic or fall back. Profile-specific tests are selected independently from legacy
RSA integration tests, while all existing default/all-feature tests remain intact.

Core regression matrix: mobile/envelope and authorization/cache =1395-test current
workspace baseline; legacy asymmetric/JWKS/SSH/default APIs =default/all-feature
suite; no-RSA profile =standalone normal graph and real consumer; tool admission
=every tracked lock/JSON receipt; bounds =runtime/Kani helpers; browser/AI/cloud/
physical-device =not applicable to this local JWT feature. No new native authority.

Evidence rows filled during execution: hygiene, read-before-change and readiness;
red graph failure; candidate lock/source/provenance/OSV; real JWT negative/positive
cases; isolated startup/race cases; Kani bounds; legacy/workspace/static gates;
exact scope, docs and independent critique/verification/retro. No blank Actual
Result cell or undisposed finding may survive closure. Rollback is disabling the
unreleased profile; never disabling authentication or persisting keys as a fallback.

## Exact file allow-list (18)

- `Cargo.lock`
- `crates/secure_identity/Cargo.toml`
- `crates/secure_identity/src/lib.rs`
- `crates/secure_identity/src/token.rs`
- `crates/secure_identity/src/jwt_hmac.rs`
- `crates/secure_identity/tests/jwt_hmac_profile.rs`
- `fixtures/jwt-hmac-consumer/Cargo.toml`
- `fixtures/jwt-hmac-consumer/Cargo.lock`
- `fixtures/jwt-hmac-consumer/src/main.rs`
- `scripts/check-jwt-hmac-profile.py`
- `.github/workflows/ci.yml`
- `crates/secure_identity/README.md`
- `CHANGELOG.md`
- `docs/dev-guide/jwt-hmac-profile.md`
- `docs/slo/current/RUNBOOK-jwt-hmac-profile.md`
- `docs/slo/design/jwt-hmac-profile-threat-model.md`
- `docs/slo/lessons/jwt-hmac-profile-m1.md`
- `docs/slo/completion/jwt-hmac-profile-m1.md`

Read first: existing token/authenticator/error, capability/JWKS/workload/SSH code,
manifest/feature graph and current JWT tests; pinned jsonwebtoken11 crypto/key/
signature source; ring HMAC source; root admission, Kani wrappers and CI contracts.
The resource-bound policy is local to the new reduced profile. If a fix needs an
existing asymmetric test/source outside this list, pause and present the concrete
conflict rather than broadening this scope. Publication is a later contract.

Status: user confirmed 2026-10-14; M1 done, 2026-10-14.


## Milestone tracker

| Milestone | Status | Started | Finished |
|---|---|---|---|
| M1 reduced profile / actual consumer proof | done | 2026-10-14 | 2026-10-14 |
| M2 coordinated publication / consumer migration | done | 2026-10-15 | 2026-10-15 |

## Sequential critique

CEO: hold scope. Preserve legacy defaults and give the internal-service consumer a proven reduced graph; do not pretend optional feature selection eliminates RSA from arbitrary feature-unified applications.
Engineering: hold scope. Vendor JWT11 uses a process-global provider. Own OnceLock caches a checked install result, with an explicit startup hook; foreign installation cannot be guessed compatible. Existing default/asymmetric tests stay intact while the standalone fixture supplies new-profile proof.
Security: hold scope. Unsupported algorithms/key families/JWK operations must return typed errors; no callback panic placeholders, handwritten parser or disabled validation. Staged fixture locks receive their own scan with no root exception inheritance before compilation.
Design: hold scope. Unreleased guide must distinguish legacy/default and minimal consumer behavior, keys/JWT bounds, initialization order and publication status. No cloud/device proof or JWT guarantee outside this profile.

## Evidence log

| Check | Actual result |
|---|---|
| Hygiene/readiness | Clean slo/jwt-hmac-profile-m1 worktree at 753a00d; crates/manifests/locks/CI source identical to fully checked 0.3.0 e1f4506. Baseline six-lock official OSV passed 1448 package occurrences. |
| Red consumer graph | Metadata resolution ran offline without scripts/builds; isolated existing no-default-feature consumer normal/build graph includes rsa and the required assertion fails for that exact reason. Candidate external identities/checksums remain a root subset. No fixture code compiled. |
| Baseline runtime | Focused all-feature secure_identity baseline passed; current 1395-test workspace 0.3.0 evidence retained for identical source. |
| Candidate admission | Official OSV v2.7.0 all seven locks/1643 package occurrences passed after explicit positive consumer admission. No fixture exception inheritance; root external dictionaries identical and consumer 195-package lock has no rsa. |
| Real JWT/startup/race/bounds | Two selected real JWT/bounds tests, one private key utility test and six actual isolated consumer/startup scenarios pass. Cold-cache graph resolution failed before fix and passes with locked build-free fetching. |
| Kani/workspace/static | Legacy all-feature workspace 1395 tests and workspace/selected-profile/consumer Clippy pass; formatter/workflow regressions pass. Actual CI 38643646234 Linux 0.68 red/green kernels verified: both mutant assertions fail, both original kernels pass, all thirteen covers SATISFIED, automatic assertion reachability enabled and no stubs. Final hardened-classifier/platform revalidation passed on implementation78b3bc7 (CI 38645105658). |
| Scope/docs/verify/retro | 17 changed paths within the confirmed 18; root lock unchanged. All required CI/security/package/doc gates pass on78b3bc7. Cold-cache, parser and ownership review findings reproduced/fixed; actual raw proofs pass the strict classifier. Guide, threat model, lessons and completion filled; no additional issue filing. |

User AGENTS dependency admission takes precedence over a fixture-runtime red run: unrepaired standalone fixture cannot inherit root RSA exceptions. The real outcome graph assertion is red first; behavioral scenarios are authored before implementation and execute only after the reduced graph is admitted. No compile/setup error or unadmitted vulnerable fixture is presented as passing evidence.

Behavioral tests authored before implementation in jwt_hmac_profile.rs; execution waits for reduced fixture/root admission. Focused existing identity baseline 203 tests pass. Expected pre-fix graph failure is captured without compiling the RSA-containing fixture.

Admission correction inside approved scope: the generic gate deliberately excludes fixture directories. The approved profile checker calls that unchanged core with an in-memory lock list extended only by the exact non-vulnerable consumer Cargo.lock. All inventory/checksum/native/source-scoped exception/snapshot checks remain active; no fixture advisory inherits root exceptions. CI invokes this explicit all-lock admission before compiling the executable consumer. No new helper/workflow file outside the eighteen-file list is required.

Kani execution uses the repository's already approved 0.68.0 Linux CI bootstrap, with unchanged verifier source graph and SDK SHA 32e2b484d73ede0bbf64a2cf0879c4259422497d8aec4ee67d448de9ae7843d3. Local older 0.67.0 SDK is not selected. This reuses existing CI provisioning, not a new tool identity/version/graph; all seven locks are admitted before its source build. No new source file or tool recipe is required.

Independent review found cold-cache metadata failed before scanning because the checker forced offline resolution of all platforms. Reproduced in an empty task-owned Cargo cache without compiling, then removed offline restriction while retaining locked, build-free metadata. Cargo verifies retrieved package checksums; exact graph/source/subset review and all-lock OSV still precede execution. No new version/identity or source-exception leak is admitted. Review found no concrete bypass, key exposure or unsupported initialization race.


## Kani scope report (inline within confirmed eighteen files)

Suitability: two bounded deterministic kernels; no protocol/concurrency proof.
Version: repository-approved source-verified 0.68.0 and SDK checksum 32e2b484d73ede0bbf64a2cf0879c4259422497d8aec4ee67d448de9ae7843d3.
This specific admitted recipe supersedes the generic skill's 0.67 default;
the user-confirmed file allow-list supersedes its extra verify-report pathname.
No source/tool recipe or extra report file is added. Inputs: three HMAC kinds,
all usize lengths on Linux x86_64; no symbolic heap/loop/unwind assumption or stub.
External specifications: JWA key minimum 32/48/64 and unpadded tag lengths 43/64/86;
complete token <=65536 bytes. Kernels compare independent expectations, not their
own byte helpers. Red test weakens key minimum and ignores separator/tag budget;
require exactly two positively classified failures with expected harness names,
restore source even on failure, then require exactly two SUCCESSFUL green results.
Actual kernel verdict verified in CI 38643646234; final hardened-classifier CI passed in CI 38645105658. No assertion/property, counterexample or solver
failure is hidden. Crypto, entropy, process interleavings, I/O and memory erasure
remain unproved; real runtime/subprocess evidence covers selected behaviors.

CI regression follow-up: Windows OSV source serialization is accepted only when
it exactly equals a requested lock path with forward slashes; the saved raw JSON
is unchanged and the original inventory validator still rejects missing, duplicate,
relative and unrequested sources. Five explicit path/inventory cases pass locally;
actual Windows seven-lock admission and complete platform validation passed. Semgrep's argv/current_exe findings
are confined to the unpublished, unprivileged six-process regression harness:
fixed scenario names, no credentials or authority decisions. Two exact rule
annotations document that boundary. All platform lanes now finish independently
and retain admission/proof artifacts even when a gate fails. No production
scanner/core file, advisory exception, dependency identity or allow-list changed.

Additional real JWT rejection cases pass: unsigned alg=none, genuine HS384/HS512 tokens under the HS256 validator, and configured key lengths 0, 31 and 1025. No production change was required; selected profile Clippy also passes.

Kani diagnosis from retained actual 0.68 logs: both original policy assertions
were SUCCESS, but legacy old output used raw CBMC exits and counted successful
reachability probes as failures. Upstream 0.68 call_cbmc.rs confirms Old bypasses
Kani property post-processing. The gate now uses regular output, retains automatic
assertion reachability, requires actual policy assertion FAILURE in each mutant
and SUCCESS in each restored harness, and requires all thirteen named covers
SATISFIED. Covers include all three algorithm boundaries, empty/oversize and
usize::MAX domains. No assertion, memory/overflow check or source/tool graph is
disabled; actual regular-mode verdict passed, including the final hardened classifier. The hidden-file
artifact correction now retains raw reports/logs on every completed platform.

Actual proof evidence: https://github.com/kerberosmansour/SunLitSecurityLibraries/actions/runs/38643646234
Verified Linux 0.68 result: two actual mutant policy failures; both restored
kernels verified, thirteen explicit covers SATISFIED, automatic assertion
reachability enabled, no stubs and source restored. Exact raw red/green logs
also pass the subsequently hardened production classifier. No concurrency,
cryptographic strength, entropy or key-copy-erasure proof is claimed.

Independent review's concrete classifier and ownership findings are fixed.
A synthetic fixture exercised the actual old nested classifier and reproduced
contradictory-result acceptance before correction. Ten mixed/malformed/duplicate/
post-summary/unsupported/unreachable-policy cases now reject; both real logs
accept. Two same-byte POSIX file/parent symlink regressions reject, and all
consumer/ordinary locks are ownership-checked before metadata and again at proof.
Final implementation78b3bc7 exact-source CI and strict proof classification passed. The following closeout is docs-only; source remains unpublished until M2.

## Final self-review and regression matrix

All self-review answers yes: exact allow-list, graph/admission before builds,
real outcome/BDD rejection cases, compatibility, mandatory static/platform
checks, positive red/green Kani with independent expectations/non-vacuity, docs,
complete evidence and clean ignored artifacts. oc-jwt-hmac-1 / cuj-jwt-hmac-1=pass.
Core identity/profile/default/workload/package/security outcomes=pass; cloud/UI/AI/
hardware consumer integration=not_applicable (this local Rust source milestone
introduces none). No required scenario is pending or waived.

Detected work ledger: cold metadata, omitted positive fixture inventory, exact
Windows source aliases, unpublished-harness Semgrep review, hidden artifact upload,
legacy verifier output classification, mixed/post-summary records and ownership
aliases are all fix_now/resolved with the recorded evidence. Publication is
operator_action for separately proposed M2, already tracked by issue54; no new
upstream defect/accepted-risk waiver or duplicate issue is filed.

Completed2026-10-14. Lessons: docs/slo/lessons/jwt-hmac-profile-m1.md.
Completion: docs/slo/completion/jwt-hmac-profile-m1.md.
Final code verification: https://github.com/kerberosmansour/SunLitSecurityLibraries/actions/runs/38645105658


## M2 confirmed publication contract

# Rust issue54 M2 — confirmed coordinated 0.4.0 publication contract

Publish M1's reviewed HMAC-only identity profile after its actual platform/security
checks and red/green Kani proofs pass and its source is merged. M1 passed actual platform/security/Kani checks and merged at
4c2e4da763d5baa65442ce0ae10cc2f516db6678. No publication or
implementation outside this contract is authorized by this document alone.

## Contract and compatibility

- Publish all twelve coordinated crates as **0.4.0**, using the proven family
  release/signing tooling. The public feature groups and migration for prior
  no-default-feature asymmetric callers justify a minor pre-1.0 release. Changes
  to the other eleven crates are mechanical family-version/docs updates only.
- Preserve all external package versions/sources/checksums, audit records and
  exact expiring advisory dispositions. Root and positive consumer lock updates
  change only local family versions. Any new external graph identity stops this
  scope for a separately reviewed admission batch.
- Update install examples, changelog and concrete migration: existing defaults
  preserve asymmetric/SSH behavior; no-default callers explicitly opt into
  asymmetric-jwt/ssh-public-keys as appropriate; the reduced consumer selects
  jwt-hmac and initializes its checked provider at trusted startup before vendor
  encoding. Keep fixed ProviderUnavailable failure, bounds and restart guidance.
- Advertise the optional HMAC profile honestly in CycloneDX: no rsa package in
  the exact reviewed isolated normal/build graph, not arbitrary additive feature
  unions, default package graphs or absence of RSA code from ring. Default full
  package SBOMs may legitimately contain rsa. Existing public-key reachability
  exceptions remain; they are never inherited by the reduced positive fixture.
- Keep provider/process/key-size/entropy/internal-copy limits. No new crypto,
  unsafe code, KEK export, custom token parser, algorithm-policy broadening,
  verifier version or production cloud configuration is permitted.
- Use script-disabled archive resolution, all-lock and exact candidate-package
  OSV, full graph/source/provenance review **before** compilation or upload.
  Verify immutable registry bytes, VCS source, exact checksums, committed approval
  record, twelve official-schema SBOMs, exact workflow signature identity and all
  GitHub asset digests. No expected/fabricated registry approval values.
- Use the same reviewed candidate uploader and immutable release producer as
  0.3.0; no helper/tool recipe/CI file is changed in M2. User's existing merge and
  publication authorization applies once all concrete gates pass.

Data: package/source/release evidence Public; synthetic test credentials Public;
production keys/tokens Restricted. Proactive controls: Leverage Security Frameworks
and Libraries, Validate All Input and Handle All Errors and Exceptions. Threat
model: the confirmed M1 jwt-hmac model; publication introduces source/package/
provenance substitution boundaries only. Kani/TLA for these mechanical release
edits: not applicable; actual M1 bounded proofs remain a mandatory prerequisite.
AI tolerance: not applicable, no AI feature. No refactor beyond these edits.

## Operator readiness and outcome

Require successful M1 merged source and independent review, complete platform CI,
actual two-kernel red/green Kani evidence, clean dedicated release branch,
unchanged external identities and proven registry/GitHub signing authentication.
Do not expose tokens or substitute a different scanner/verifier when unavailable.

oc-jwt-publish-1 / cuj-jwt-publish-1: a consumer obtains 0.4.0, follows the packaged
migration/startup instructions, selects the reviewed reduced graph and authenticates
its real HS256 JWT with correct rejection behavior. Registry archives and signed
release assets exactly match reviewed, admitted source. Cross-layer validation:
source/API/docs/declaration -> exact archive/lock admission -> compilation and
real reduced-profile runtime -> registry checksum/VCS -> signed assets/SBOM.

BDD: default consumer behavior remains compatible; explicit reduced consumer has
no rsa in its normal/build graph; previous reduced asymmetric callers have a
working explicit migration; a foreign/frozen provider still fails closed; malformed/
wrong algorithm/oversize inputs still reject. Changed external identity, scanner
error, tampered registry/source/signature or missing M1 proof stops publication.
Review signed artifact/registry bytes rather than writing contrived doc tests.

Evidence rows: source/readiness, exact scope, unchanged external graph, seven-lock
admission, candidate archive/source/provenance scans, workspace/profile regressions,
registry bytes/VCS/checksums, official SBOM schema/signatures/asset digests and
issue54 closeout. Core regressions: identity/profile=actual M1 and release consumer
pass; other libraries=workspace CI; mobile custody/qualification=retained 0.3 limits;
cloud/browser/AI integration=not applicable to this Rust package release.

## Exact file allow-list

The 37-file count includes 24 mechanical family manifest/README entries. Immutable
registry/signature artifacts are release outputs, not permission for code changes.
The task's outputs/ deliverables and private work/ evidence are separate from this
repository source allow-list. Issue/PR/release operations use existing authority.

- `Cargo.toml`
- `Cargo.lock`
- `README.md`
- `CHANGELOG.md`
- `crates/secure_authz/Cargo.toml`
- `crates/secure_authz/README.md`
- `crates/secure_boundary/Cargo.toml`
- `crates/secure_boundary/README.md`
- `crates/secure_data/Cargo.toml`
- `crates/secure_data/README.md`
- `crates/secure_device_trust/Cargo.toml`
- `crates/secure_device_trust/README.md`
- `crates/secure_errors/Cargo.toml`
- `crates/secure_errors/README.md`
- `crates/secure_identity/Cargo.toml`
- `crates/secure_identity/README.md`
- `crates/secure_network/Cargo.toml`
- `crates/secure_network/README.md`
- `crates/secure_output/Cargo.toml`
- `crates/secure_output/README.md`
- `crates/secure_privacy/Cargo.toml`
- `crates/secure_privacy/README.md`
- `crates/secure_resilience/Cargo.toml`
- `crates/secure_resilience/README.md`
- `crates/security_core/Cargo.toml`
- `crates/security_core/README.md`
- `crates/security_events/Cargo.toml`
- `crates/security_events/README.md`
- `fixtures/jwt-hmac-consumer/Cargo.lock`
- `declarations/cyclonedx-1.6-capabilities.json`
- `declarations/release-0.4.0-packages.json`
- `docs/dev-guide/release-process.md`
- `docs/dev-guide/jwt-hmac-profile.md`
- `docs/slo/current/RUNBOOK-jwt-hmac-profile.md`
- `docs/slo/design/jwt-hmac-profile-threat-model.md`
- `docs/slo/lessons/jwt-hmac-profile-m2.md`
- `docs/slo/completion/jwt-hmac-profile-m2.md`

Status: user confirmed 2026-10-15; M2 done. M1 readiness prerequisites verified.


### M2 sequential critique and readiness

CEO: hold scope. A consumer cannot use the reviewed profile from 0.3.0; publish
0.4.0 with the explicit migration, without importing pending dependency batches.
Engineering: hold scope. Partial immutable multi-crate publication is recoverable
only by checking actual registry versions/checksums before retrying. Reuse the
reviewed sequential uploader and commit the real approval record before tagging.
Security: hold scope. Registry/source substitution and graph drift (CWE-494/829)
are mitigated by archive admission, downloaded immutable-byte comparison and exact
signature identity, not inferred clean scans. Variant analysis is bounded to the
unchanged package/producer helpers; no new helper authority is introduced.
Design: no UI surface; skip UI review. The packaged README links an immutable
migration guide and names startup failure, feature-union and proof boundaries.
No new ask/scope finding. Legacy Markdown threat model has no schema companion;
review is degraded for abuse-ID stability, with no invented canonical IDs.

| M2 evidence | Actual result |
|---|---|
| Hygiene/readiness | Clean dedicated release/jwt-hmac-0.4.0 at main4c2e4da; M1 all platform/Kani checks passed and merged. No prior-retro issues returned. |
| Baseline | Fresh seven-lock OSV: 1643 package occurrences, exit0; actual focused all-feature baseline passed. |
| Scope/external graph | 34 paths within 37 confirmed; root/consumer external package dictionaries identical, only 12/6 local versions changed. No runtime/helper/workflow/audit edits. |
| Admission/runtime | Fresh candidate seven-lock gate passed 1643 occurrences; separate generic six-lock gate passed 1448. All 1,395 workspace tests, selected 2+1 profile/key tests, six real source consumer cases, formatter and Clippy passed. All 12 exact archive scans/reviews passed before compilation/upload. |
| Registry/signatures/schema/assets | All 12 registry archives/checksums/VCS match source 49612e1. Actual approval PR #140 merged/tagged 318512a; signing 38687007436 succeeds. All 27 exact identity/issuer/commit/ref signatures, 12 official-schema SBOMs,54 server asset digests and downloaded bytes verify. |
| Outcome/retro/closeout | Registry-only consumer 195 packages/zero rsa, exception-free OSV and all six real scenarios pass. Outcome/CUJ complete; lessons and completion files written, every finding disposed. Broad task remains open. |

Surface map: no new request, parser, crypto or secret API. Reuse secure_identity's
reviewed profile plus the existing package admission/producer/signing boundaries.
Production release tokens remain restricted; build/scan environments omit them.
No new capability gap. Rollback before publication is the branch; afterwards,
versions are immutable and any repair needs a new release, never retag/repack.


### M2 runtime verification / self-review closeout

Pass 0: actual registry-only consumer outcome/CUJ passes; no source-path dependency
substitutes for the published crates. Pass 1: real HS256 identity passes. Pass 2/3:
real claim/signature/key/algorithm/boundary rejections and all six isolated
provider/startup/race scenarios pass. Pass 4: seven-lock and package OSV/source/
provenance checks, source PR's complete SAST/static/security suite and unchanged
external dictionaries pass. Pass 5: exact registry/producer/signature/schema/asset
bytes pass. Pass 6: all 37 confirmed paths maximum, no runtime/helper/workflow edits,
legacy 1,395 tests and platform checks pass. UI/DAST/cloud/device gates are N/A for
this package publication; existing mobile physical/consumer limits stay explicit.

Fresh source CI 38685528995 raw Kani logs were independently reclassified: two
actual mutant failures, two restored kernels, 13 satisfied covers, automatic
assertion reachability. No crypto/concurrency/entropy/erasure proof claim.

Detected ledger: historical mobile-version prose and triggered-job count were
fix_now and corrected before affected commit/merge. No undisposed or newly
accepted-risk row. Self-review all yes within the confirmed contract. M2 lessons:
`docs/slo/lessons/jwt-hmac-profile-m2.md`; completion:
`docs/slo/completion/jwt-hmac-profile-m2.md`.

M2 explicit migration: no-default asymmetric-jwt+ssh-public-keys profile passed15 SSH and36 capability integration tests (51 total), preserving the actual public APIs under the documented explicit selection.
