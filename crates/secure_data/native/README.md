# Native mobile wrapping bridges

These sources implement `NativeKeyBridge` operations for application bindings.
They wrap a transient 32-byte data key. `secure_data` remains responsible for
application-state envelope encryption. No Rust-facing wrapping-key export exists.

## Android

`MobileKeyBridge.java` uses AndroidKeyStore AES-256-GCM and an opaque `SecretKey`.
Each operation reports `KeyInfo.getSecurityLevel()` for the actual key. Software,
trusted-environment and StrongBox policies are explicit; a strict request fails
if the observed level is weaker. A StrongBox creation failure has no fallback.
Keys require an unlocked device. Unwrap looks up an existing key and never creates
one. Alias/version length-prefixed AAD and an exact 61-byte versioned frame bind
ciphertext to its identity. App-private, no-backup lock files contain no key data.

Call native operations synchronously on a worker thread. Shared provider clones
serialize through Rust; the native nonblocking file lock also excludes another
process of the same application. Busy, missing, locked, invalidated, unavailable
and authentication failures return fixed enum values; there is no automatic
retry. The two-second check is a **result deadline after resource closure**, not
hard preemption of Android OS calls. A stalled OS call can exceed it. No detached
key operation is started; applications must reconcile cancellation only after
native completion. Physical-device timing/lock/invalidation remains unqualified.

`Unwrapped.borrowedBytes()` is a temporary native buffer. Copy directly into the
Rust `Zeroizing` data-key owner and always call `close()` in a finally path before
releasing the native operation. Never serialize this buffer through JavaScript,
log it or persist it. Rejected unwrap paths overwrite their owned array, including
resource-close failures. Ordinary JVM array clearing does not guarantee removal
of internal provider copies, optimized-away writes, crash dumps or aborted work.
The Android KEK remains inside AndroidKeyStore. Existing platform algorithms,
JDK and Android SDK supply crypto; no Maven/Gradle package is required.

## Qualification

The manifest, instrumentation runner and Activity are a **generated debuggable
fixture app**, never a production manifest. The control Activity is not exported;
qualification explicitly verifies that an external launch is denied. They contain only generated keys and ciphertext. Native
fixtures use unique namespaces and persist cleanup ownership before creating a
key. A failed preference commit stops before native key creation. The runner
requires a receipt for a separately created, task-owned emulator: isolated data
directory, live emulator PID/port and a matching owner token. It never claims
ownership merely from an `emulator-*` serial. It does not download SDKs or wipe
an existing user AVD.

Create the isolated emulator and ownership receipt through your authorized test
operator. Receipt JSON fields are `serial`, `pid`, `dataDirectory`, `ownerToken`;
`dataDirectory` must be the receipt directory's `emulator-data`. Set the same
64-hex owner token as the emulator's `debug.sunlit.qualification_owner` property.
The receipt is an operational identity check, not an adversarial OS boundary.

```sh
python3 scripts/qualify-mobile-native.py --self-test
python3 scripts/qualify-mobile-native.py --platform android \
  --device emulator-5558 --ownership /path/to/qualification/emulator-ownership.json \
  --output /path/to/qualification/normal
python3 scripts/qualify-mobile-native.py --platform android \
  --device emulator-5558 --ownership /path/to/qualification/emulator-ownership.json \
  --fault-injection --output /path/to/qualification/faults
```

The normal build compiles the production bridge source unchanged. The fault
build instruments a copy in the output directory to throw during lock release
and observe clearing of a generated plaintext buffer; the production bridge has
no fault API. Tests exercise namespace-persistence failure, real wrapping,
process restart/recovery, frame/alias/version tampering, software-policy rejection
and key deletion/no recreation. The runner replaces stale reports at invocation
start and emits a run-identified terminal report even on build/device failure.
Cleanup runs in finally, records its own failure, then removes the fixture app.
Device loss can prevent cleanup; a failed cleanup must be resolved by the test
operator and never reported as a clean pass. On iOS, failed Keychain deletion
suppresses uninstall and retains the namespace marker. A subsequent run must
complete prior cleanup before creating another key; uninstall alone is not
Keychain cleanup.

Observed Android emulator custody is SOFTWARE. This proves no physical TEE,
StrongBox, backup exclusion, device-lock or reset behaviour. Those claims require
physical-device qualification. No hardware-support release claim is permitted
from these reports. The iOS simulator likewise supplies software evidence only. Native reference
sources are provided; consuming application FFI and physical qualification remain
explicit integration requirements.


## iOS

`MobileKeyBridge.swift` uses Security/Keychain and CryptoKit AES-GCM. Every existing
key must have `WhenPasscodeSetThisDeviceOnly` accessibility and synchronization
disabled before it is used. A newly created wrapping key is generated with
`SecRandomCopyBytes`, stored only in this Keychain class, then read and validated.
The current `LAContext` checks passcode-authentication prerequisites without UI;
Keychain remains the final authority. Missing passcode, locked/unavailable native
services, weaker key attributes and failed/duplicate creation fail closed. There
is no accessibility downgrade, creation retry or unwrap recreation. Alias/version
AAD and frame format match Android. Only transient DEKs cross the reviewed native
binding; no long-lived wrapping-key getter exists.

Apple documents this class as excluded from backup, iCloud synchronization and
escrow. Removing or resetting the passcode discards its class keys. Existing
protected state can then be unrecoverable. The consuming app must require trusted
re-enrolment and explicitly initialize new state/key identity; it must not silently
recreate a missing key to acknowledge stale state. Restoring a backup does not
restore the wrapping key. A stricter hardware policy rejects this software
wrapping implementation; Keychain's device protection is not a Secure Enclave
wrapping-operation claim.

References: [Apple Keychain data protection](https://support.apple.com/en-au/guide/security/secb0694df1a/web),
[accessibility class](https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly),
[CryptoKit random default nonce](https://developer.apple.com/documentation/cryptokit/aes/gcm/seal(_:using:nonce:authenticating:)).

Native operations are synchronous and share a nonblocking process-wide `NSLock`.
The two-second check rejects late results; it cannot preempt an OS call. No
asynchronous/detached native operation is started. The consuming bridge must keep
its lane/owners alive through completion before reconciling cancellation.
`NativeUnwrappedKey.withBytes` borrows bytes only for its closure. Copy immediately
into Rust's zeroizing DEK owner, never let the pointer escape, and always call
`close()`. Rejected/closed owned buffers are cleared. Swift Data copy-on-write and
CryptoKit/Keychain internal copies prevent a universal memory-erasure guarantee;
no abort/crash/snapshot or memory-locking protection is claimed.

The runner generates a vendor-only Xcode simulator target, with no package
references or script phases and automatic package resolution disabled. Xcode
emits the proper simulator-specific entitlements. Local temporary SDK output
avoids File Provider FinderInfo attributes that invalidate code signing; project
and terminal evidence remain in the chosen output. No physical certificate,
provisioning profile or device deployment is requested. The live simulator's
UUID/name/runtime/owner token must match a receipt created by the test operator.

```sh
python3 scripts/qualify-mobile-native.py --platform ios \
  --device YOUR_TASK_SIMULATOR_UUID \
  --ownership /path/to/qualification/simulator-ownership.json \
  --output /path/to/qualification/ios
```

Receipt fields: `deviceUDID`, `name` (`SunlitNative-` plus a generated UUID),
`runtime`, `ownerToken` (64 hex). Set the matching simulator launchd environment
`SUNLIT_NATIVE_OWNER` after creating/booting that isolated simulator. The fixture
records its exact generated namespace atomically before creating a Keychain key.
On a simulator unable to satisfy passcode prerequisites, qualification reports
`blocked` and does not use a weaker class. Passing tests prove the simulator's
native calls/attributes and process recovery; physical backup exclusion, passcode
removal/reset, lock state, reinstall, Secure Enclave, TEE/StrongBox and timing
remain unqualified. The generated simulator/emulator should be shut down and
removed by its owning operator after the test session; never erase a user device.

## Published integration

These reference sources are included in the `secure_data` 0.3.0 registry archive. Use [the migration guide](https://github.com/kerberosmansour/SunLitSecurityLibraries/blob/v0.3.0/docs/dev-guide/mobile-bridge-migration.md) from the source repository when implementing an application binding. The fixture manifests/runners are qualification assets and must not become a production app configuration. Physical devices, backup/passcode transitions and consumer reconciliation remain separate qualification gates.
