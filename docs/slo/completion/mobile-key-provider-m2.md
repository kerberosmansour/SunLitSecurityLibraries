# M2 completion — native mobile wrapping reference sources

Status: done for the user-confirmed 14-file native-reference scope, 2026-10-14.
The iOS passcode-only accessibility correction was separately confirmed.

Android uses opaque AndroidKeyStore AES-256-GCM and actual KeyInfo level, enforcing
explicit software/TEE/StrongBox policy. iOS uses Keychain passcode-only device
storage and CryptoKit AES-GCM, validates attributes, reports software wrapping
and never downgrades. No new package, unsafe Rust, Rust-facing KEK getter or
parallel application-state encryption path was introduced.

Actual SDK outcome tests pass on iOS26.5 simulator and Android36.1 emulator:
generated randomDEK wrapping, ciphertext/frame persistence, process restart and
recovery, authenticated tamper rejection, wrong alias/version and key deletion/
no recreation. Android injected close/namespace failures and iOS test-helper/
cleanup ownership regressions failed first, then passed. Five host failure tests
pass; native/host Semgrep reports zero findings/errors across eight scanned paths.
M1 Rust source/baseline remains unchanged. Source-review findings are disposed.

Success cleans only generated fixture namespaces/state and removes their apps.
Failed iOS Keychain cleanup retains the app/namespace for retry; prior cleanup
must pass before another key is created. Task device identities are verified.
Physical backup/passcode reset/lock/reinstall/hardware, SDK memory-copy erasure,
hard OS preemption and downstream FFI/exactly-once reconciliation are not qualified.
Native result deadlines never imply hard OS-call cancellation.

M3 publication/migration is not complete or confirmed by this file. Issue98 stays
open; Guardian's downstream proof remains separate. Evidence/commands and residual
owners are in the current runbook, native README and threat model. No new issue
filing is needed: the existing capability request owns the remaining work.
