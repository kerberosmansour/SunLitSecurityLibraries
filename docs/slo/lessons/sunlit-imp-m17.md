# Lessons Learned — M17: OWASP ZAP DAST Integration

## What went well

1. **No Rust code changes required**: M17 is purely scripts, CI config, and documentation. The smoke service from M16 and its OpenAPI spec worked as the perfect DAST target without modification.
2. **zap_check.py self-tests passed immediately**: Simulated clean and high-finding reports validated both the exit-0 (clean) and exit-1 (high finding) paths without needing Docker or a live ZAP scan.
3. **ZAP Replacer pattern for JWT auth**: Using ZAP's Replacer add-on to inject the Bearer token via CLI config is clean — no custom ZAP scripts or authentication hooks needed.
4. **Baseline file with mandatory justifications**: Requiring a `justification` field for every suppressed finding prevents silent false-positive accumulation.

## What was tricky

1. **Docker daemon dependency**: The entire scan pipeline requires Docker to be running. The preflight check in `zap_scan.sh` catches this early, but local development without Docker Desktop running is a hard blocker for scan testing.
2. **JWT generation in bash**: Generating a valid HS256 JWT in bash requires careful base64url encoding (padding removal, `+/` to `-_` translation) and `openssl dgst`. Getting the exact format right for the smoke service's `TokenValidator` is error-prone — the secret, issuer, and audience must match `SecurityConfig::dev()` exactly.
3. **ZAP API scan vs baseline scan**: ZAP has multiple scan modes (`zap-api-scan.py`, `zap-baseline-scan.py`, `zap-full-scan.py`). For an API with an OpenAPI spec, `zap-api-scan.py` is correct — it understands the spec and tests endpoints with proper request shapes.
4. **Cross-platform Docker networking**: Linux needs `--add-host=host.docker.internal:host-gateway` while macOS/Windows have `host.docker.internal` built in. The script handles both.

## Design decisions

1. **Gate on High/Critical only**: Medium and lower findings are reported but don't fail the build. This avoids CI flakiness from informational ZAP findings while still catching real security issues.
2. **Separate check script (Python)**: `zap_check.py` is a standalone Python script rather than bash parsing. JSON report parsing is cleaner in Python, and the script can be tested independently of Docker/ZAP.
3. **TSV rule file**: ZAP's native rule configuration format (TSV) is used directly rather than inventing a custom format. Each rule maps to IGNORE/WARN/FAIL.
4. **CI workflow runs on Linux only**: Docker-in-Docker on GitHub Actions requires Linux runners. macOS/Windows runners don't reliably support Docker for ZAP.

## Patterns to reuse

- JWT generation in shell using `openssl dgst -sha256 -hmac` — reusable for any HS256 JWT testing
- ZAP Replacer CLI config pattern for injecting auth headers without custom scripts
- Baseline suppression file with mandatory justification — applicable to any SAST/DAST tool
- Preflight check pattern in shell scripts (check Docker, python3, cargo before starting work)
