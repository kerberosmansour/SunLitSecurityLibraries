# Mobile provider M2 lessons

Use platform SDK wrapping only for DEKs; reuse the Rust envelope for state AEAD.
Guardian/Broker supply interface/custody discipline, not an existing mobile wrap
backend. No package dependency or Rust KEK getter was needed.

Keychain backup exclusion required correcting the planned accessibility class.
The user confirmed WhenPasscodeSetThisDeviceOnly/no fallback; document unrecoverable
state and re-enrolment after passcode removal/reset. Device-only alone is not this
contract. Software Keychain wrapping is not Secure Enclave wrapping.

Keep secret ownership through resource closure. The real Android close-failure
regression exposed a return discarded after plaintext ownership had already been
transferred; nested resource scope now closes first and failures wipe the buffer.
Persist fixture cleanup ownership before creating keys and check commit results.
An iOS failed delete must retain its app/namespace; uninstall is not Keychain cleanup.
The rejection test helper must not catch its own sentinel as the expected error.

Generated app reports can be read mid-write; wait within a deadline or publish
atomically. Always invalidate stale host passes and emit a terminal run identity.
An emulator serial alone is not ownership. Verify task identity before mutation;
nonexported Android control plus instrumentation removes unnecessary exposure.

Xcode emits simulator-specific entitlements needed by Keychain. Ad hoc manual
signing alone was insufficient. File Provider FinderInfo on app directories broke
signing; an owned local SDK temp build avoids it. No physical profile/certificate
or weaker accessibility workaround was used.

Native positive recovery/tamper/deletion pass on both installed runtimes. These
remain software evidence. Preserve explicit physical, cancellation, SDK-copy and
hard-preemption limits in M3; never turn simulation into a hardware claim. M3 must
provide a reviewed release and migration guidance before closing issue98. All
follow-up is already scoped by issue98; no new upstream issue or scope expansion.
