# Completion Summary — sg-gate-a Milestone 3

## Goal completed
`secure_boundary::safe_types::SafeUrl` now rejects every CIDR on Sunlit Guardian's v3-K2 required blocked list. Variant-analysis coverage: 12 per-CIDR rejection tests + 4 edge-upper tests + 4 negative controls + 2 scheme sanity tests, each named after its target. The `SafeUrl` rustdoc enumerates all 12 CIDRs with one-line reasons per entry. Downstream engineers and security agents get an integration guide at `docs/dev-guide/safe-url-ssrf.md`.

## Files changed
- `crates/secure_boundary/src/safe_types.rs` — extended `is_private_ipv4` (+1 branch: `224/4`) and `is_private_ipv6` (+3 branches: `fe80::/10`, `ff00::/8`, `::/128`); expanded `SafeUrl` rustdoc with full blocked-CIDR table.
- `crates/secure_boundary/tests/sg_gate_a_safeurl_cidrs.rs` — NEW 22-scenario test file.
- `docs/dev-guide/safe-url-ssrf.md` — NEW integration guide.
- `docs/slo/completed/RUNBOOK-sunlit-guardian-gate-a.md` — Milestone Tracker: M3 `done`.

## Tests added
- 22 scenarios in `sg_gate_a_safeurl_cidrs.rs`:
  - 12 per-CIDR rejection: `rejects_cidr_10_slash_8`, `rejects_cidr_172_16_slash_12`, `rejects_cidr_192_168_slash_16`, `rejects_cidr_169_254_slash_16`, `rejects_cidr_127_slash_8`, `rejects_cidr_224_slash_4`, `rejects_cidr_0_slash_32`, `rejects_cidr_fc00_slash_7`, `rejects_cidr_fe80_slash_10`, `rejects_cidr_loopback_v6`, `rejects_cidr_ff00_slash_8`, `rejects_cidr_ipv6_unspecified_slash_128`.
  - 4 edge-upper: `rejects_cidr_172_31_slash_12_upper`, `rejects_cidr_239_255_upper`, `rejects_cidr_fd00_slash_7_upper`, `rejects_cidr_fe80_slash_10_upper`.
  - 4 negative controls: `accepts_public_ipv4_8_8_8_8`, `accepts_public_ipv4_1_1_1_1`, `accepts_public_ipv6_2606`, `accepts_public_hostname`.
  - 2 scheme sanity: `rejects_javascript_scheme`, `rejects_file_scheme`.

## Runtime validations added
None additional for M3 — the test file is the validation. The existing `secure_smoke_service/tests/e2e_sg_gate_a_m1.rs` continues to exercise `SafeUrl` indirectly through the extractor chain.

## Compatibility checks performed
- `cargo test --workspace` — 1112 passing, 0 failing.
- `cargo test -p secure_boundary --test sg_gate_a_safeurl_cidrs` — 22 passing.
- `cargo test -p secure_boundary --doc` — 33 doctests passing (the new `SafeUrl` rustdoc doctest runs as part of this).
- `cargo doc -p secure_boundary --no-deps --all-features` — zero warnings.
- `cargo clippy -p secure_boundary --all-features --no-deps -- -D warnings` — clean.
- `cargo check -p secure_boundary --no-default-features` — green.
- All pre-M3 `SafeUrl` doctest examples continue to pass (verified — none were modified semantically; only the rustdoc around them expanded).

## Documentation updated
- `secure_boundary::safe_types::SafeUrl` rustdoc: full 12-CIDR table, "What `SafeUrl` does NOT do" caveats, extended examples (public URL, loopback rejection, AWS IMDS rejection, IPv6 link-local rejection, scheme rejection).
- `docs/dev-guide/safe-url-ssrf.md` — new integration guide.

## .gitignore changes
- None required.

## Test artifact cleanup verified
- `git status` clean.

## Deferred follow-ups
- IPv4-mapped IPv6 detection (`[::ffff:127.0.0.1]`) — not currently caught. Deferred as explicit follow-up per runbook scope.
- DNS rebinding: connect-time IP re-validation — documented as a caveat; implementation is out of scope.
- URL parser quirks identified during read (IPv6 bracket heuristic, port-detection edge cases) — noted but not fixed. No evidence they affect Gate A semantics.

## Known non-blocking limitations
- The blocked set is code (not runtime-configurable). Downstream services that want a stricter local policy extend the private functions in a fork, not at runtime. This is deliberate per Google's variant-analysis rationale.
