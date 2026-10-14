# Capability reuse and first SLO milestone

Requested scope: implement the larger open capability requests as well as maintenance fixes. This expands the completed dependency-maintenance work into several independently reviewable features.

## Source evidence

| Source | Revision inspected | Reusable material | Limits |
|---|---|---|---|
| Sunlit Guardian | main `56c2c4d7ab1c1e6e96df2da1b9f2bb98458da59e` | `IosNativeBridge`/`AndroidNativeBridge` shape, platform custody levels and native bridge conventions | Attestation signing is a different primitive from envelope-key wrapping; Android signing implementation is stubbed. Neither inspected mobile bridge implements wrap/unwrap. |
| Sunlit Agent Secrets broker | main `3e855d0148e9cafa84e045262eb6f1a15432c88c` | Native-store identity checks, bounded zeroizing ownership, fail-closed error mapping, durable reopen/commit evidence | Existing desktop custody supports macOS/Windows/Linux; no mobile daemon or mobile wrapping API. Its private custody anchor and no-export protocol must remain private. |
| Existing secure_data macOS branch | local `ce3fea8d841e504ef2370825f4d915401e95045c`, provider commit `a212631` | Existing envelope-provider structure and key/nonce/frame validation | Separate unmerged local work; do not overwrite it. Its generic-password provider reads a KEK into Rust, so copying it does not satisfy the mobile no-KEK-export contract. |
| SunLitSecurityLibraries main | `9a76505a6e8ac8384d3c0aedc2ce6d4eff4b133e` | Sealed KeyProvider, random DEKs, zeroizing DataKey, envelope AEAD, typed DataError and mobile storage policies | Current mobile-storage feature has policy types only. |

Official platform constraints: [Apple passcode device-only accessibility](https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly), [Apple synchronization attributes](https://developer.apple.com/documentation/security/ksecattrsynchronizable), [Android Keystore and hardware levels](https://developer.android.com/privacy-and-security/keystore). chub returned no matching Keychain/Keystore reference, so the official platform sources are the documentation fallback.


Four objects: envelope owns AEAD/persisted format; adapter owns DEK generation,
metadata/bounds/policy; trusted native bridge owns KEK/native operations and
cancellation/timeout; consumer owns provider lifetime and persisted envelopes.
No changes to existing format, sealing, native broker protocol or Guardian.
New public types are additive under mobile-storage. Disable feature to roll back;
persisted envelopes remain recoverable with the original native bridge/key.


M2 reuses platform SDK primitives rather than a parallel state cipher. Native
AES-GCM wraps only 32-byte DEKs; secure_data owns application envelope AEAD. iOS
uses the user-confirmed passcode-only device class, synchronization false and
software wrapping. Android uses opaque AndroidKeyStore AES-256 and actual
KeyInfo security level; native creation cannot silently fall back. No new
package, unsafe Rust or Rust-facing KEK API was introduced. Reference sources
and fixtures are separated; nonexported Android Activity/instrumentation and
simulator-only Xcode entitlements never become production manifests.

Actual software-native recovery is qualified in both installed SDK runtimes.
Hardware/device lifecycle and application FFI remain separate evidence, including
Guardian's exactly-once reconciliation. Keychain passcode removal/reset cannot
be hidden behind a fallback: consumers must re-enrol explicitly. iOS cleanup
failure retains the application/namespace rather than losing a Keychain recovery
record. OS calls are synchronous; a result deadline does not hard-preempt them.
