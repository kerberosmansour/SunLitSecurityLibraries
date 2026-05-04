# Completion Summary — M17: OWASP ZAP DAST Integration

## Goal

Integrate OWASP ZAP (Checkmarx ZAP) as an automated DAST scanner against `secure_smoke_service`. Create the scan script, ZAP configuration, alert baseline, scan rules, and CI workflow. The build must fail on high/critical ZAP findings.

## Deliverables

| Deliverable | File | Status |
|---|---|---|
| ZAP scan orchestrator script | `scripts/zap_scan.sh` | ✅ Created |
| ZAP report parser / CI gate | `scripts/zap_check.py` | ✅ Created |
| ZAP rule customisation | `scripts/zap-rules.tsv` | ✅ Created |
| False positive baseline | `scripts/zap-baseline.json` | ✅ Created |
| CI workflow | `.github/workflows/zap.yml` | ✅ Created |
| README.md ZAP section | `README.md` | ✅ Updated |
| ARCHITECTURE.md ZAP pipeline | `ARCHITECTURE.md` | ✅ Updated |
| .gitignore ZAP artifacts | `.gitignore` | ✅ Updated |

## Evidence Log

| Check | Command | Expected | Actual | Pass/Fail |
|---|---|---|---|---|
| Baseline test suite green | `cargo test --workspace` | All pass | All pass | ✅ Pass |
| Clippy clean | `cargo clippy --workspace --all-targets -- -D warnings` | No warnings | No warnings | ✅ Pass |
| zap_check.py clean report | `python3 scripts/zap_check.py --report /tmp/clean.json` | Exit 0 | Exit 0 | ✅ Pass |
| zap_check.py high finding | `python3 scripts/zap_check.py --report /tmp/high.json` | Exit 1 | Exit 1 | ✅ Pass |
| zap_scan.sh preflight | `bash scripts/zap_scan.sh` | Builds, starts service, fails at Docker (not running) | Builds, starts service, fails at Docker pull | ✅ Pass |
| Baseline suppression loading | `zap_check.py --baseline` | 3 suppressions loaded | 3 suppressions loaded | ✅ Pass |
| No untracked test artifacts | `git status` | Clean tree | Clean tree | ✅ Pass |
| .gitignore updated | Manual review | ZAP patterns present | `output/zap-report.*` added | ✅ Pass |
| Post-milestone test suite | `cargo test --workspace` | All pass | All pass | ✅ Pass |
| Post-milestone clippy | `cargo clippy --workspace -- -D warnings` | No warnings | No warnings | ✅ Pass |

## Compatibility

- No Rust source code was changed — all existing tests, APIs, and services are unaffected
- Existing CI workflow (`.github/workflows/ci.yml`) is unchanged
- `secure_smoke_service` routes and middleware ordering preserved
- `secure_reference_service` unmodified

## Notes

- Full ZAP scan could not be run locally because Docker Desktop was not running. The scan script, report parser, and CI workflow are fully implemented and tested with simulated reports. Live ZAP validation will occur when Docker is available or in CI on first push.
- The ZAP JWT uses the smoke service's dev-only secret from `SecurityConfig::dev()` — this is intentionally hard-coded for testing and documented as non-production.
