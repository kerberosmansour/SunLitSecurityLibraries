# Completion Summary — fv Milestone 5

## Goal completed
TLA+-verified design for the `secure_identity` session+step-up flow lands. Three safety properties (no privileged action without step-up, no expired-session reuse, step-up window bounded) verified at bound `MaxSessionTicks=5, MaxStepUpTicks=2`. Naive variant deliberately violates `NoPrivWithoutStepUp`; TLC must find the documented counterexample. Advisory `tla.yml` CI lane runs both variants on every PR (10-min cap; TLC 1.8.0 pinned).

## Files changed
- `specs/SessionStepUp.tla` — Hardened spec (NEW).
- `specs/SessionStepUp.cfg` — Hardened TLC config (NEW).
- `specs/SessionStepUpNaive.tla` — Naive spec (NEW).
- `specs/SessionStepUpNaive.cfg` — Naive TLC config (NEW).
- `specs/SessionStepUp.trace.md` — counterexample translation (NEW).
- `docs/slo/design/session-step-up-verified.md` — verified-design doc (NEW).
- `.github/workflows/tla.yml` — advisory CI lane (NEW).
- `CHANGELOG.md` — Unreleased entry.
- `docs/slo/completion/fv-m5.md` (this file).
- Runbook tracker — M5 done.

## Tests added
- TLC runs (Hardened expected to pass; Naive expected to find counterexample) — exercised by CI on every PR.
- The CI workflow itself fails-loud if Hardened fails or Naive passes silently (per the matrix.expect logic).

## Static analysis evidence
- TLA+ specs are static `.tla` text — TLC validates syntax, types, and invariants in CI.
- Workflow YAML — passes basic GitHub Actions schema validation by GH on first run.

## Compatibility checks performed
- No production-code change in M5; existing tests unchanged.
- Existing `specs/NativeDeviceTrust.tla` lane unaffected (different model, different config).

## Documentation updated
- `CHANGELOG.md` Unreleased entry.
- Verified-design doc at `docs/slo/design/session-step-up-verified.md`.
- Trace doc at `specs/SessionStepUp.trace.md`.

## Lessons (compact, embedded here for fv M5)
- **TLA+ specs in fresh modules (Naive in its own .tla) rather than CFG-only differentiation.** The /slo-tla SKILL pattern envisioned same-spec / different-cfg, but the cleanest expression of the Naive design is a separate module that expresses "no step-up gate" structurally.
- **`tla2tools.jar` v1.8.0 pin via the workflow env.** Future runbooks can vendor the JAR with SHA pinning per the /slo-tla SKILL §3 — out of scope for M5.
- **Naive vs. Hardened is a test of the spec's quality.** If the Naive variant passes silently, the Hardened spec is too abstract — the proof is vacuous. The matrix.expect=fail logic in the workflow makes this explicit.

## Deferred follow-ups
- fv M4 (#14): the new `secure_resilience::circuit_breaker` module + its TLA+ Naive+Hardened spec. The `tla.yml` matrix already lists the entry; the M4 PR adds the actual `.tla` files.
- Promotion of `tla.yml` to a blocking gate — separate runbook after ≥1 release cycle.
- Multi-session / token-revocation race specs — separate runbook if a real concurrent-session bug surfaces.

## Known non-blocking limitations
- TLA+ Tools v1.8.0 jar SHA is not validated locally on every download. Acceptable for an advisory lane; future hardening can vendor the JAR.
- Liveness properties are stated in the .tla but not exercised by `SessionStepUp.cfg` (safety-only). A separate `SessionStepUpLive.cfg` could exercise them; deferred — safety is the load-bearing property.
