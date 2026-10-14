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
