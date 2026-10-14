---
id: mobile-key-provider
prefix: mobile-key-provider
version: 4
stack: Rust
ai_component: false
baseline: cargo test -p secure_data --features mobile-storage --locked
---
# Mobile key provider

User confirmed M1 scope and exact nine-file allow-list on 2026-10-14. M2 and M3
remain proposed until their own concrete contracts are confirmed. M1 is in_progress.
No carry-forward from prior retros: this is M1. Separate dirty native-provider
work in the user's original checkout is preserved.

## First milestone contract: mobile adapter (M1)

Goal: consumers can supply reviewed native Keychain/Keystore wrap/unwrap operations to a sealed first-party KeyProvider; long-lived KEKs never enter Rust.

Important design rule: reuse secure_data envelope encryption and the Guardian bridge pattern. The bridge is trusted native code, not an untrusted caller/plugin. Wrapping metadata and custody posture must be returned by the operation itself; a separate preflight claim cannot substitute for operation-level evidence. Never expose the broker's private root key or general secret retrieval API.

| Contract row | M1 commitment |
|---|---|
| Inputs | Issue 98, existing KeyProvider/envelope/mobile policy, the inspected source revisions above |
| Outputs | Mobile adapter, typed native error and custody contract, first-party deterministic test backend, executable BDD, API guide |
| Interfaces | Additive `providers::mobile` surface behind existing `mobile-storage`; KeyProvider remains sealed; existing envelope format remains compatible |
| Exact files allowed to change | `crates/secure_data/src/providers/mobile.rs`; `crates/secure_data/src/providers/mod.rs`; `crates/secure_data/src/error.rs`; `crates/secure_data/README.md`; `docs/slo/current/RUNBOOK-mobile-key-provider.md`; `docs/slo/design/mobile-key-provider-reuse.md`; `docs/slo/design/mobile-key-provider-threat-model.md`; `docs/slo/lessons/mobile-key-provider-m1.md`; `docs/slo/completion/mobile-key-provider-m1.md` |
| Files to read first | In this repo: `kms.rs`, `envelope.rs`, `mobile_storage.rs`, `error.rs`, `providers/mod.rs`, `lib.rs`, Cargo manifests; Guardian: native bridge files; broker: platform identity/error handling. Every external read is identified by repo/revision above. |
| New dependencies | None for the Rust adapter; native platform integration is separately scoped |
| Migration | None in M1; native binding migration examples and actual devices are M2 |
| Compatibility | Existing providers and envelope AEAD unchanged; no deterministic production key; no native-store I/O from non-mobile CI |
| Data classification | Restricted: transient DEKs; Confidential: consumer data; only synthetic test material |
| Proactive controls | OWASP C8 data protection: envelope boundary; C5 input validation: bounded alias/version/wrapped frame; C10 error handling: fixed value-free native errors |
| Resource bounds | 32-byte fresh DEK; alias/version ASCII and <=128/64 bytes; wrapped key <=8192 bytes; one serialized native operation per provider; no unbounded retry; backend must impose native-call timeout |
| Invariants | Native bridge receives a fresh transient DEK but never returns a KEK; unwrap returns exactly 32 zeroizing bytes; version/alias and platform posture checked; invalidation cannot trigger key recreation during decrypt |
| Abuse scenarios | Altered alias/version/frame fails; software backing cannot satisfy hardware policy; synchronized/backed-up iOS key rejected; unavailable/locked/partial native operation fails closed |
| Exemplar | Existing KeyProvider sealing/DataKey zeroization; Guardian trusted native bridge; broker bounded error mapping |
| Anti-exemplar | Android null stubs; shell-based secret-store calls; generic-password KEK export; static production key; silent software/hardware equivalence |
| Refactor budget | No refactor beyond direct implementation |
| AI tolerance | N/A — no AI component |
| Debugger | Deterministic bridge state/operation counters and typed outcomes; debugger only if a state transition is ambiguous |
| Static gates | cargo fmt/check/clippy; all secure_data features; locked dependency graph, native guard and vet |
| Rollback | Additive feature can be disabled; never downgrade encrypted persisted data into plaintext; immutable released formats stay readable with original providers |
| Forbidden shortcuts | No unsafe FFI, raw KEK export, secret logging, fake production support, ignored tests, placeholder native success or widening dependency updates |

BDD: round trip uses real envelope AEAD; fresh DEKs differ; reconstructed provider with same test native state decrypts after restart; altered ciphertext/wrapped key/alias/version fails; missing/locked/invalidated key and unavailable bridge return typed fixed errors; iOS backup/sync posture rejected; Android software/TEE/StrongBox policy distinguished; concurrent callers serialize correctly; malformed native key length rejected before AEAD; static dev provider is unchanged and remains non-production.

Outcome scenario `oc-mobile-key-provider-1`: a consumer persists an envelope, restarts its provider, recovers the original generated plaintext, and tamper/unavailable-key cases never produce plaintext. Cross-layer assertion: native test wrapping → real secure_data envelope encryption → reconstructed native test state → real envelope decryption. This qualifies adapter behavior, not a physical device.

Measurement: deterministic operation counters show one native wrap per encryption, one native unwrap per decryption and no retry. Native recovery latency is measured in M2 and cannot be claimed from the test bridge. Owner: repository maintainer; readout at milestone closeout.

Validation commands: `cargo test -p secure_data --features mobile-storage --locked`; `cargo test -p secure_data --all-features --locked`; `cargo clippy -p secure_data --all-targets --all-features --locked -- -D warnings`; `cargo fmt --all -- --check`; `python3 scripts/check-native-dependencies.py`; `cargo vet --locked`.

Definition of done: all scenarios have red-first evidence and passing real envelope tests, exact allow-list verified, no new dependency/unsafe block, value-free errors and transient DEK zeroization reviewed, existing providers unaffected, independent review clean, evidence/lessons recorded. No native-production claim or issue closure until M2 qualification and M3 publication.

Proposed subsequent milestones: M2 native iOS/Android binding, device/simulator qualification and migration; M3 coordinated release, declarations and downstream admission evidence. Their exact contracts will be authored after M1 confirmation, as required by slo-plan.


## §5A Measurement contract
Deterministic operation counters: one wrap/encryption, one unwrap/decryption,
zero implicit retries/recreation. Maintainer owns readout at M1 closeout.
No device latency or hardware qualification is inferred from CI.

## §5B Secure value and security contract
Value wedge: recover generated persisted data after restart through a typed
native bridge while long-lived KEKs stay native. See mobile-key-provider-threat-model.md.
Operator readiness: safe_to_continue_without_blockers=true for adapter tests;
no physical native support is claimed until M2. Existing six-lock admission
passes 1448 package occurrences, baseline tests pass, native guard passes.
Security bundles: B (application code: SAST/SCA/abuse) and F (mobile: custody,
backup and permission checks). Bounds, metadata, failures, zeroization,
serialization, tamper and restart are their concrete M1 checks. Native platform
permission evidence is not_applicable until M2.
Detected work: missing native wrap/unwrap tracked in issue98 (fix M1 adapter,
native implementation M2); no invented Guardian capability. No new dependency.

## §5C Outcome validation contract
cuj-mobile-key-provider-1: encrypt generated plaintext, persist envelope,
reconstruct provider from persistent test native state, recover exact plaintext;
tampered envelopes/native failures never return plaintext.
Layers: public envelope API applicable; AEAD applicable (real AES-GCM);
provider adapter applicable; native bridge deterministic synthetic test only;
physical device not_applicable (M2); UI/network not_applicable (library).
Cross-layer assertion compares real AEAD recovered bytes after provider restart.
Core regression matrix: static dev provider pass baseline; classical encryption
pass baseline; mobile policies pass baseline; PQ/full provider features pass
M1 all-feature run; physical native qualification not_applicable (M2).

## Sequential critique
Stored inline to honor the user-confirmed file allow-list.
CEO: hold scope. Restart recovery gives a reviewable consumer boundary; physical
custody qualification must not be implied by a deterministic bridge.
Eng lead: hold scope. The confirmed contract already requires operation-bound
metadata, persistence, serialization and native failure/partial-operation tests.
No extra architecture change or file is needed. Future cancellation must end
native work before the bridge releases its operation; this is part of the trusted
bridge's existing timeout/serialization responsibility, documented explicitly.
Security: hold scope. V6 key-management sprawl / V8 backup exfiltration mitigated
by tm-mobile-key-provider-abuse-1/2; V7 error leakage eliminated at this adapter
boundary with value-free enums. Native truthfulness/timeout are residual trust
requirements for M2, not properties Rust can infer. Variant analysis limited to
new adapter plus existing sealed KMS/envelope paths; no new KEK getter, subprocess
or unsafe FFI. Degraded mode: no machine-readable threat-model file in the approved
allow-list; no abuse-ID-stability claim.
Design: skipped, no UI surface. No ask findings or scope expansion.

## Evidence log
| Check | Actual result |
|---|---|
| Repo hygiene | clean task branch slo/mobile-key-provider-m1 based on107f096; main protected; original user checkout preserved |
| Admission/baseline | six locks/1448 OSV pass; declared mobile-storage baseline passes |
| Surface map | secure_data envelope and DataKey reused; native callback is trusted bounded bridge, KEKs never returned; no HTTP/SQL/shell |
| BDD/outcome red | Seven compiled tests failed for expected unavailable behavior; strengthened restart test failed against a newly created independent native store |
| Implementation / BDD green | Eight mobile tests pass, including real AEAD and JSON persistence/restart; generated native-state KEK prevents unrelated-store recovery |
| Full feature/static compatibility | 199 all-feature tests including41 doctests pass; declared feature baseline pass; clippy -D warnings/fmt/native guard pass; unchanged lock graph; vet146full/49partial/305exempted |
| Independent review | No confirmed adapter bug; wrap/unwrap concurrency and real persistent test-key ownership gaps strengthened; native lifecycle residuals explicit |
| Runtime/outcome QA | Pass0 real envelope→JSON persistence→new provider→same native-state key recovers generated48byte plaintext; four tamper variants and unrelated store fail; platform/fault/metadata/concurrency scenarios pass |

## Verification — SLO Passes 0–6
Stored inline to stay inside the confirmed allow-list.
| Pass | Runtime/evidence | Result |
|---|---|---|
| 0 outcome/cuj | Real envelope API/AEAD, JSON persistence, reopened provider with generated zeroizing native test-state key; unrelated native store cannot decrypt | pass |
| 1 happy | Fresh DEKs differ; 32-byte keys; recovered generated plaintext exact | pass |
| 2 degraded | Missing/locked/invalidated/unavailable/incomplete/authentication errors; invalid/empty requests never call native bridge | pass |
| 3 partial/bounds | Native short key, incorrect alias/version, oversized/empty frame and long version rejected; failed custody never reaches AEAD | pass |
| 4 BundleB | Live OSV6locks/1448, unchanged root/tool locks, native guard, admitted Semgrep16rules/3files no findings, exact frozen vet; no new unsafe or secret-debug output | pass |
| 4 BundleF | Explicit iOS/Android operation custody matrix and backup rejection | pass |
| 4 native/DAST | Physical native qualification belongs M2; no HTTP surface added | not_applicable |
| concurrency | Wrap/wrap, wrap/unwrap and unwrap/unwrap share one operation lane across clones | pass |
| 5 AI | No AI component | not_applicable |
| 6 measurement | Counters enforce one operation/call and zero retry/decrypt recreation; native latency deferred to M2 | pass |

Self-review: all yes — exact nine-file diff, compiled red-first tests, real
cross-layer outcome, compatibility/feature tests, typed nonsecret errors,
zeroizing key ownership and no KEK API, no new dependencies/unsafe, no fake
native support, inspected residuals and no unrelated edits. Native truthfulness,
allocation limits, cancellation and OS lifecycle remain M2 prerequisites.

## Tracker
| Milestone | Status | Started | Completed | Evidence |
|---|---|---|---|---|
| M1 adapter | done | 2026-10-14 | 2026-10-14 | lessons/mobile-key-provider-m1.md; completion/mobile-key-provider-m1.md |
| M2 native reference qualification | done | 2026-10-14 | 2026-10-14 | lessons/mobile-key-provider-m2.md; completion/mobile-key-provider-m2.md; physical properties unqualified |
| M3 publication/downstream | proposed — contract not yet confirmed | — | — | Issue98 remains open until reviewed release and migration |


## M2 confirmed native contract

# Mobile provider M2 — concrete proposed scope

M1 is reviewed in [PR130](https://github.com/kerberosmansour/SunLitSecurityLibraries/pull/130).
M2 supplies reviewed native wrapping implementations and executable platform
qualification without changing the sealed Rust API or importing a new package.
The existing Guardian native bridge conventions and Broker's bounded custody
failure handling are reused; signing-only stubs are not copied as wrapping.

Native iOS implementation: Apple Security/Keychain + CryptoKit AES-GCM. A fresh
32-byte wrapping key lives only in Keychain and transient native memory, uses
WhenPasscodeSetThisDeviceOnly, synchronizable=false, and has no Rust KEK getter.
It is explicitly software wrapping with device-protected storage; it never
claims Secure Enclave/hardware wrapping. Native AES-GCM wraps the transient DEK
with exact alias/version authenticated data; decrypt does not recreate a key.

Native Android implementation: platform AndroidKeyStore AES-256-GCM; getKeyInfo
reports the actual operation key's security level. Explicit software/TEE/
StrongBox policy is enforced before returning success; hardware requests cannot
fall back silently. Missing/locked/invalidated/error outcomes are fixed values.

No Swift Package Manager, Maven/Gradle, Rust, npm or third-party crypto dependency
is added. Compile/tests use existing Xcode26.6, iOS26.5/18.6 simulators and the
installed Android36.1 SDK/emulator/JDK. If a new dependency proves necessary,
stop before installation and apply exact script-disabled OSV/provenance admission.

Exact allow-list in SunLitSecurityLibraries:
- crates/secure_data/native/ios/MobileKeyBridge.swift
- crates/secure_data/native/ios/Qualification.swift
- crates/secure_data/native/ios/Info.plist
- crates/secure_data/native/android/MobileKeyBridge.java
- crates/secure_data/native/android/QualificationActivity.java
- crates/secure_data/native/android/AndroidManifest.xml
- crates/secure_data/native/README.md
- scripts/qualify-mobile-native.py
- crates/secure_data/README.md
- docs/slo/current/RUNBOOK-mobile-key-provider.md
- docs/slo/design/mobile-key-provider-reuse.md
- docs/slo/design/mobile-key-provider-threat-model.md
- docs/slo/lessons/mobile-key-provider-m2.md
- docs/slo/completion/mobile-key-provider-m2.md

Behavior/measurement: native wrap→persist frame→process stop/relaunch→unwrap
recovers generated32byte DEK; changed alias/version/frame, deleted key and partial
operation never return plaintext; software custody cannot satisfy hardware
policy. Fixed aliases are prefixed by a generated qualification identifier.
Native tests delete only their own generated keychain/keystore items and emulator
app data; never consumer keys. Frames <=8192, alias/version<=128/64 ASCII, exact
32byteDEKs, no secret logs/key files, serialized operations and no implicitretry.
A synchronous native operation completes before ownership is released; bridges
must not spawn detached key operations. Native error/cleanup paths are reviewed.

Qualification records simulator/emulator as software evidence. Hardware TEE/
StrongBox and physical-device lock/backup/invalidation require actual devices;
those gates remain explicit and block any claim of qualified hardware support.
The supplied native sources are callable bridge implementations; application FFI
binding must map mutable native DEK buffers into Rust Zeroizing and clear native
copies, with no JS/plaintext serialized persistence. Guardian's exactly-once
application reconciliation remains a downstream acceptance gate, not a claim
of this library milestone. Release/migration is M3 after reviewed evidence.

DoD: real native platform tests, process restart/tamper/deletion/custody evidence,
source review and library regression gates pass; unsupported physical properties
are stated precisely; full diff stays inside this list; no new dependency,
unsafe Rust, deterministic production key, raw KEK export or fake hardware claim.


M2 status: in_progress; user confirmed exact scope/14 files. Read M1 lessons.
Baseline: M1 allfeature199tests pass; clean task branch; existing installed SDKs
identified; no new package graph. No physical Android connected.
M2 critique (sequential): CEO hold scope (real custody implementation, honest
software evidence); eng hold scope (same Rust interface, platform-controlled
key stores and explicit process lifecycle); security hold scope (threat rows
1–5 carry forward, fixed errors and no exported KEK; hardware/cancellation
claims require actual evidence); design skipped (no product UI). No extra ask.

M2 secure surface: native Keychain/Keystore and transient DEKs. Platform crypto
APIs provide wrapping; secure_data remains the application-state envelope AEAD.
OS-native wrapping primitives protect DEKs only, not a duplicate application
encryption path. No shell secret-store command or app-local key file.

M2 evidence: baseline/hygiene passed. Android/iOS native red-first qualification
compiled and failed for expected unavailable/input behaviour. Both installed
SDK runtimes now pass native wrapping, persisted ciphertext/frame, process stop/
relaunch recovery, tamper/wrong alias/version and deletion/no recreation. Native
reference sources are software-qualified; physical properties remain unqualified.

Confirmed policy correction: user approved WhenPasscodeSetThisDeviceOnly/no fallback and documented re-enrolment on passcode removal/reset. This supersedes the original class.


## M2 evidence and verification

| Check | Actual result |
|---|---|
| Scope/hygiene | Task branch slo/mobile-key-provider-m2; exact 14-file allow-list; no Rust/npm/SPM/Maven dependency or unsafe Rust added; M1 Rust baseline unchanged |
| Native BDD red | Actual Android APK unavailable stub failed before implementation; actual compiled iOS app input scenario failed before validation; no fixture dependency installation |
| Android outcome | Android 36.1 generated emulator: native wrap→encrypted frame/digest persistence→force-stop→new bridge unwrap matches generated32byteDEK; normal production-source build passes |
| Android faults | Injected lock-close failure failed clearing before fix, then passed; failed namespace commit failed before fix, then rejects without creating a key. Tamper/alias/version/software→hardware/StrongBox rejection, deletion/no-recreate, close/clear and cleanup pass |
| iOS outcome | Xcode26.6 / iOS26.5 generated simulator: strict Keychain attributes, native CryptoKit wrap→persistence→terminate/relaunch→sameDEKdigest; tamper/alias/version/deletion/no-recreate/closed-owner tests and cleanup pass |
| iOS faults | Rejection helper could catch its own expected error: native regression failed first, then sentinel moved outside catch. Host cleanup failure regression lost marker before fix; now app/namespace retained, prior cleanup required before seed |
| Host regressions | Five Python tests pass, covering partial report, missing ownership, stale report/build failure, assertion/timeout/cleanup failures, retained iOS Keychain cleanup marker; no SDK calls in host unit tests |
| Source review | Android five findings plus report race/exported control fixed; iOS two concrete findings fixed with red-first evidence. No known undisposed finding |
| Static/admission | Native/host Semgrep eight scanned paths, zero findings/errors. Three exact subprocess sites annotate validated integer/serial and fixed executable/remote command, not a blanket suppression. Swift compiled with source warnings treated as errors and separately reviewed. Cargo/root/tool locks unchanged |
| Operator identity | Separate task emulator data/PID/port/token and simulator UUID/name/runtime/token verified before installation; no user device erased or installed |
| Cleanup | Own generated keys/state cleared and apps removed on successful runs. Android finally cleanup+uninstall; iOS failed deletion suppresses uninstall to preserve marker. SDK build temp directory removed. Device loss is an explicit failure |

SLO verification: Pass0 native wrapping/persistence/restart outcome passes on both
runtimes. Happy/degraded/tamper/partial and buffer-owner checks pass; source/static
security checks pass. No browser/product UI or AI surface. Measurements distinguish
observed Android SOFTWARE and iOS software wrapping from hardware; the two-second
result deadline is not hard OS-call preemption. Device lock/passcode removal/reset,
backup/reinstall, hardware, memory locking/abort/internal-copy erasure and consumer
FFI/exactly-once reconciliation remain explicitly unqualified. No unsupported
physical or production application-integration claim closes those gates.

M2 is done for the confirmed native-reference/software qualification scope.
M3 publication/migration is still proposed, not authorized by this completion.
Issue98 stays open until the reviewed crate and consumer guidance are published;
Guardian's downstream device/reconciliation proof is a separate acceptance gate.
