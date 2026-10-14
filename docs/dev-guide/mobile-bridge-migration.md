# Mobile native bridge migration — 0.3.0

Enable `secure_data = { version = "0.3.0", features = ["mobile-storage"] }`.
The sealed `providers::mobile::MobileKeyProvider<B>` adapts an application-owned,
reviewed `NativeKeyBridge` to existing envelope encryption. Native reference
sources are packaged under `native/ios` and `native/android`; they are SDK source
references, not a ready-made Tauri plugin, JNI library or Swift/Rust FFI binding.
Guardian's bridge discipline and Broker's private custody boundary informed the
interface. Their application integration has not been delivered by this release.

## Compatibility

The envelope format and existing providers are unchanged. `DataError::MobileKeyProvider { kind }`
is a new typed variant when `mobile-storage` is enabled. `DataError` is already
non-exhaustive, so existing downstream wildcard matches remain valid. Handle the
new kind explicitly where useful and preserve fixed outcomes without logging
native diagnostics or keys.
Other coordinated crates have mechanical version updates and unchanged APIs.
Do not reinterpret an existing provider's ciphertext as a native wrapped frame.
Migration of old data requires an authorized read with its original provider and
fresh encryption with the new provider, followed by durable ciphertext commit.
Preserve the old ciphertext until the new persisted envelope is verified.

## Implement the native binding

1. Review `NativeKeyBridge`, `NativeWrappedKey`, `NativeUnwrappedKey` and the native
   SDK implementations. Implement `wrap(&mut self, alias, data_key)` and
   `unwrap(&mut self, alias, version, wrapped_key)` with `Send` futures. Native
   creation belongs only to wrap; unwrap must never create or retry a missing key.
2. Pass bytes directly between Rust and native memory. Native unwrap returns a
   borrowed transient buffer: Android `Unwrapped.borrowedBytes()` or Swift
   `NativeUnwrappedKey.withBytes`. Copy directly into the Rust `DataKey`
   (`zeroize::Zeroizing<Vec<u8>>`) owner, then close the native owner in every path.
   Apply bounds before allocating or copying: exactly 32 DEK bytes, printable
   ASCII alias/version of at most 128/64 bytes and wrapped frame at most 8192
   bytes. The supplied native reference frame is exactly 61 bytes.
3. Map native fixed error categories to `MobileKeyError`. Return the exact alias,
   version and actual custody from the completed operation. Never substitute a
   device-wide preflight check for the key's operation-bound metadata. Rust
   validates metadata consistency; it cannot attest a dishonest native bridge.
4. Own the native call until completion, on a worker thread. Keep the unwrap
   buffer owned until native resources have closed successfully, clear rejected
   copies, and serialize cancellation with completion. The supplied references'
   two-second check is a result deadline, not OS-call preemption. Do not detach
   work after a caller cancels or free borrowed Rust bytes while native code uses
   them. A consumer binding must qualify these ownership rules independently.
5. Keep aliases/version namespaces stable across application restarts and separate
   applications/tenants. Reuse a provider or its clones to share serialization;
   independent providers must retain the supplied native store coordination.

Do not transfer DEKs/KEKs through JavaScript, JSON, logs, app preferences or a
plaintext database. Do not expose a KEK getter. The supplied native references
require no Maven/SPM package; review any new consumer dependency under the OSV
admission rule before builds or installation scripts.

## Select policy and persist state

Construct `MobileKeyProvider::new(reviewed_bridge, platform, storage_policy)`.
Use `MobilePlatformPolicy::IosDeviceOnly` for the supplied iOS reference. Android
policies distinguish `AndroidSoftwareAllowed`, `AndroidHardwareRequired` and
`AndroidStrongBoxRequired`. `MobileStoragePolicy::encrypted(classification)`
permits explicitly chosen software custody; `hardware_backed(classification)`
requires qualified hardware. Do not relax a hardware requirement to make a test
pass. The supplied iOS software implementation and Android software keys fail
hardware-required policy. A custom hardware bridge requires independent proof of
its operation-bound metadata and key properties.

Call `encrypt_for_storage(plaintext, alias, &provider).await` and persist only the
returned `EnvelopeEncrypted` using the existing serializer/storage boundary.
Acknowledge success only after an atomic durable commit of ciphertext. After
restart deserialize that envelope and call `decrypt_for_use(&envelope,
&provider).await`. Keep plaintext in the narrow authorized operation and clear
consumer-owned copies. The envelope decrypt API returns a byte vector; this
release does not automatically zeroize arbitrary application plaintext copies.
Reject failed authentication and reconcile interrupted writes without reverting
to plaintext. Exactly-once application completion/reconciliation is a downstream
requirement; the provider alone does not implement it.

## Key loss and re-enrolment

The iOS reference uses `WhenPasscodeSetThisDeviceOnly`, nonsynchronized and no
fallback. Require a passcode; if unavailable, return a fixed failure. Passcode
removal/reset can invalidate custody and make existing state unrecoverable.
Android missing/invalidated keys likewise fail decrypt. Never regenerate a key
under the same identity in order to claim that old ciphertext was recovered.

An authorized recovery flow must explain unrecoverable local state, authenticate
through a separate trusted enrolment/recovery mechanism, discard or preserve old
ciphertext according to application retention policy, create a fresh namespace or
version during an explicit wrap/enrolment operation, and durably encrypt new
state. Do not silently downgrade accessibility, use a desktop KEK export, or
restore plaintext. The application owns identity verification and user recovery
UX; this library provides no credential bypass or remote recovery service.

## Required consumer qualification

Real iOS simulator and Android emulator tests cover native wrap, ciphertext
persistence, process restart/unwrap, tamper and deletion failures. Android tests
also cover resource-close wiping and nonexported fixture control. These prove
software reference behavior only. Physical lock/unlock, passcode removal/reset,
backup/restore, device timing, TEE/StrongBox behavior, memory-copy properties,
application FFI cancellation and Guardian reconciliation require separate tests.
Use task-owned fixtures and namespace cleanup from `native/README.md`; fixture
applications are debuggable test assets and their manifests must not ship in a
production application. Until those gates pass, advertise only the qualified
software/reference capability and fail closed on stronger requested policy.

The repository's external locked graph, audits and expiring reachability
exceptions are preserved. Downstream resolution can differ: scan all consumer
lockfiles with the pinned official OSV scanner and review provenance before
compiling the admitted graph. OSV detects known advisories, including reported
malicious packages; it does not establish absence of unknown malware.
