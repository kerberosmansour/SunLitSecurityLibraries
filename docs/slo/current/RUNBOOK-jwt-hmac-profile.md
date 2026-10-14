---
id: jwt-hmac-profile
prefix: jwt-hmac-profile
version: 4
stack: Rust
ai_component: false
baseline: cargo test -p secure_identity --all-features --locked
---
# JWT HMAC-only profile — confirmed M1

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

Status: user confirmed 2026-10-14; in_progress.


## Milestone tracker

| Milestone | Status | Started | Finished |
|---|---|---|---|
| M1 reduced profile / actual consumer proof | in_progress | 2026-10-14 | — |
| M2 coordinated publication / consumer migration | proposed; contract not yet authored | — | — |

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
| Kani/workspace/static | Legacy all-feature workspace 1395 tests and workspace/selected-profile/consumer Clippy pass; formatter/workflow regressions pass. Kani red/green Linux 0.68 kernels remain pending CI. |
| Scope/docs/verify/retro | Pending. |

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
Current verdict pending CI. No assertion/property, counterexample or solver
failure is hidden. Crypto, entropy, process interleavings, I/O and memory erasure
remain unproved; real runtime/subprocess evidence covers selected behaviors.
