# Completion — mobile key provider M1

Added a sealed MobileKeyProvider around trusted native wrap/unwrap callbacks
under the existing mobile-storage feature. It generates fresh zeroizing32byte
DEKs, enforces bounded operation metadata/frames, rejects inadequate custody,
serializes shared operations, and returns fixed typed errors without native key
or caller metadata. Existing envelope format and providers remain unchanged.

Exact nine files: providers/mobile.rs, providers/mod.rs, error.rs, secure_data
README, current/RUNBOOK-mobile-key-provider.md, design/mobile-key-provider-reuse.md,
design/mobile-key-provider-threat-model.md, lessons/mobile-key-provider-m1.md,
completion/mobile-key-provider-m1.md. No Cargo lock/manifest or unsafe change.

Eight executable mobile scenarios plus199allfeature tests/41doctests pass.
Seven initial tests failed first, and the unrelated-store restart assertion
failed before the test backend gained generated persistent native key state.
Clippy/fmt, native guard, frozen vet and admitted SAST pass. Full evidence and
SLO runtime pass mapping are in the runbook. Bounded independent source review
found no adapter bug; its two test gaps were addressed.

Limit: M1 qualifies the Rust adapter and real envelope behavior using a test
native backend. It does not implement or attest native iOS/Android custody.
Issue98 stays open until native qualification, reviewed publication and migration
proof. No production-capability declaration is expanded in M1.
