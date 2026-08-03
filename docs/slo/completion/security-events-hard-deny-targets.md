# Completion Summary — `security_events` hard-deny tracing targets

## Goal completed

- Added a vendor-agnostic global tracing boundary for dependency targets whose spans or events may
  contain prompts, arguments, results, provider bodies, paths, identities, or other unreviewed
  runtime content.
- Prepared `security_events 0.1.3` as the release target. This artifact does not claim that the crate
  has been merged, signed, published, or consumed downstream.

## Security invariants

- A configured target root and every `::` descendant return `Interest::never()` from
  `Layer::register_callsite` and `false` from `Layer::enabled`.
- A permissive `EnvFilter`, including an explicit trace directive for a denied target, cannot
  re-enable that target.
- Textual near-prefixes and application-owned targets remain visible.
- Empty or malformed configuration is rejected before subscriber installation.
- The control drops untrusted dependency content; it does not attempt arbitrary message redaction.

## Files changed

- `crates/security_events/src/hard_deny.rs`
- `crates/security_events/src/lib.rs`
- `crates/security_events/tests/hard_deny_targets.rs`
- `crates/security_events/Cargo.toml`
- `Cargo.toml`
- `Cargo.lock`
- `README.md`
- `crates/security_events/README.md`
- `docs/dev-guide/security-events.md`
- `ARCHITECTURE.md`
- `THREAT_MODEL.md`
- `CHANGELOG.md`
- `declarations/cyclonedx-1.6-capabilities.json`

## Verification evidence

- RED receipt: the focused integration target failed to compile before implementation because
  `HardDenyTargetsLayer` and `HardDenyTargetsError` did not exist.
- Focused GREEN receipt: four tests pass, including an ungated positive control that captures all
  three secret canaries and a gated subscriber that captures none of their full values or meaningful
  prefixes.
- `cargo test -p security_events --all-features`: 83 unit/integration tests and 23 doctests pass.
- `cargo clippy -p security_events --all-targets --all-features -- -D warnings`: pass.
- `RUSTDOCFLAGS='-D warnings' cargo doc -p security_events --no-deps --all-features`: pass.
- `cargo check --workspace --locked`: pass, including the workspace and lockfile version transition
  to `security_events 0.1.3`.
- `cargo publish --dry-run -p security_events --locked --allow-dirty`: packages and verifies 34
  files (182.5 KiB, 45.1 KiB compressed); upload is correctly aborted by dry-run.
- `cargo fmt --all -- --check` and `git diff --check`: pass.
- The strict declaration reader validates the capability file against the official CycloneDX 1.6
  schema with SHA-256
  `1ebcb88a2c845ecb6ff7bee7aeabdff9422cb0347f3d6875b241bd444b7e098f`.
- `cargo audit`: exit 0 with the repository's pre-existing allowed warning for yanked `spin 0.9.8`.
- `cargo deny --locked check`: advisories, bans, licences, and sources pass; existing informational
  warnings remain unchanged.
- `cargo vet --locked`: pass (146 fully audited, 44 partially audited, 322 exempted).

## Known limitations and consumer obligations

- The layer can deny only targets the consumer configures. Consumers must inventory all dependency
  target roots and retain canary tests across dependency upgrades.
- An unlisted target or a near-prefix remains visible. This prevents accidental overreach but means
  the control is not automatic dependency discovery.
- Safe replacement telemetry must use an application-owned target and a reviewed typed schema; this
  crate does not decide which application fields are safe.
- Merge, trusted signing, crates.io publication, and downstream exact-version/checksum pinning are
  separate release steps and are not performed by this local implementation task.
