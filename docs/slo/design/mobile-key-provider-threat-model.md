# Mobile key provider threat model — M1

Boundary: application envelope metadata may be adversarial; native bridge code
is trusted and separately qualified. Transient DEKs are Restricted, encrypted
frames Confidential, diagnostics fixed nonsecret enum values. No new network,
shell, FFI, secret-store process or KEK export operation is introduced.

| ID | Actor/action/bad outcome | Control / state |
|---|---|---|
| tm-mobile-key-provider-abuse-1 | Caller swaps alias/version/wrapped frame to recover another key or ciphertext | Validate bounded metadata before native I/O; native operation echoes exact alias/version; real AEAD fails altered authenticated metadata. Mitigated; native must bind frame/alias/version. |
| tm-mobile-key-provider-abuse-2 | Application labels synchronized iOS/software Android storage as hardware custody | Operation-returned platform posture checked against explicit policy and MobileStoragePolicy; never equate device-only storage with hardware wrapping. Mitigated; native truthfulness is residual. |
| tm-mobile-key-provider-abuse-3 | Native failure returns malformed DEK/partial wrap or trigger decrypt recreation | Exact 32-byte zeroizing key, bounded nonempty frame; fixed errors; one operation with no retry/recreate. Mitigated. |
| tm-mobile-key-provider-abuse-4 | Caller feeds huge alias/version/frame to exhaust native work | ASCII length bounds before allocations/native calls; backend response limits. Mitigated; trusted backend enforces allocation/timeout bounds. |
| tm-mobile-key-provider-abuse-5 | Concurrent callers overlap a native operation or native code keeps a secret copy | Serialized provider operations; bridge must terminate its native work on cancellation and clear native transient copies. Mitigated; native lifecycle qualification M2. |

Residuals: bridge claims are not hardware attestation; M1 cannot prove native
no-export, OS accessibility, backup behavior, device lock/invalidation, timeout
or cancellation. Owner maintainer; expires at M2 qualification (before production
support/release claim). Issue98 remains open. Zeroizing Rust ownership protects
ordinary drops; it does not guarantee memory locking, abort cleanup or snapshots.


## M2 native reference boundary and disposition

The native reference implementations use existing vendor SDKs, not subprocess
secret stores. The qualification host invokes installed SDK tools only against
task-owned simulator/emulator identities; it never resolves/downloads a package.
Generated test app manifests, debug signing identities and fixtures are not
production application configuration.

| Existing abuse ID | M2 evidence / remaining boundary |
|---|---|
| abuse-1 | Length-framed alias/version AAD, exact61byte frame; real native tamper/wrong alias/version reject on both runtimes |
| abuse-2 | iOS key attributes checked against passcode-only class/syncfalse; hardwarefalse. Android KeyInfo actualSOFTWARE; strict hardware/StrongBox rejected. Physical properties remain unqualified |
| abuse-3 | Missing unwrap never creates; deleted-key recovery fails. Namespace persistence failure creates no Android key; resource-close fault clears decrypted owned buffer |
| abuse-4 | PrintableASCII bounds before I/O, exact32byte DEKs, exact61byte platform frames; two-second late-result rejection, not OS-call preemption |
| abuse-5 | Synchronous operations/nonblocking locks, Rust shared lane; native owned buffers cleared/released. App FFI/cancellation reconciliation and internal SDK/JVM/Swift copy erasure remain separate boundaries |

Detected work dispositions: all in-scope `fix_now` findings are reproduced and
fixed: Android resource-close transfer, emulator ownership, failure cleanup,
stale report, failed namespace commit, report read race and exported fixture
control; iOS rejection-helper false pass and loss of Keychain cleanup ownership.
The latter preserves the app/marker on failed delete and clears prior fixtures
before new seed. No undisposed source-review finding remains.

Residual owner: maintainer, reviewed 2026-10-14. Reference-source publication may
advertise only these limits. Physical lock/passcode reset/reinstall/backup and
hardware qualification must be completed before any corresponding production
claim; review due2026-11-14. Caller FFI must clear transient native/Rust buffers
and not release ownership while native work remains; Guardian exactly-once
reconciliation is downstream evidence, not provided by this library milestone.
Swift/JVM/SDK internals, abort/crash/snapshots and hard OS-call preemption are not
proved by ordinary buffer clearing. No new secret export or blanket waiver.
