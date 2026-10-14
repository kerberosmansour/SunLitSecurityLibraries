# Lessons learned — mobile key provider M1

The adapter reuses secure_data's sealed provider, zeroizing DataKey and envelope
AEAD; Guardian contributes the bridge shape, not an existing wrapping provider.
Broker's private native root remains private. No new dependency was required.

Outcome: generated48byte plaintext survived real envelope encryption, JSON
persistence and reconstructed provider using the same test native key state.
A fresh unrelated native store and tampered metadata/frames did not recover it.
Counters showed one native operation/call, no retries and no decrypt recreation.
Existing outcomes survived199allfeature tests including41doctests.

A fixed test-native KEK initially made restart recovery too easy. Independent
review exposed that reconnecting native state could be omitted without failure.
A regression failed first; generated zeroizing KEK ownership now resides in the
persistent test state, and an independent store fails recovery. Concurrency
coverage now exercises all wrap/unwrap combinations with shared instrumentation.
No production adapter bug was identified by the bounded review.

Errors are fixed enums. Response types deliberately omit Debug. Rust owns DEKs
under Zeroizing before entropy fill and immediately on unwrap; rejected paths
clear them on ordinary drop. These properties do not prove native copy clearing,
OS memory locking, abort cleanup or hardware custody.

Next milestone: qualify real native operations, restart, key invalidation/device
lock, backup attributes, alias/version binding, cancellation/timeouts and honest
hardware levels. Never mark software or simulator evidence as hardware proof.
M2/M3 scope must be confirmed before implementation. No new issue filing: all
product follow-up is already tracked by issue98; no upstream/process finding.
