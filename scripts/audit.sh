#!/usr/bin/env bash
# scripts/audit.sh — Local supply-chain audit runner (Linux/macOS)
# Runs the same checks as CI: secret patterns, cargo audit, cargo deny, cargo vet, OSV Scanner.
# Usage: bash scripts/audit.sh [--fix]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$WORKSPACE_ROOT"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }

ERRORS=0

echo "=== SunLitSecurityLibraries Supply-Chain Audit ==="
echo "Workspace: $WORKSPACE_ROOT"
echo ""

# ── Step 0: high-confidence secret patterns ──────────────────────────────────
echo "--- secret pattern scan ---"
SECRET_PATTERN='AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|(^|[^[:alnum:]_])gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{22,}_[A-Za-z0-9_]{59,}|xox[baprs]-[A-Za-z0-9-]{10,}|(^|[^[:alnum:]_])sk-[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35}|BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY'
if matches="$(git grep -n -I -E "$SECRET_PATTERN" -- . ':!Cargo.lock' || true)" && [ -n "$matches" ]; then
    printf '%s\n' "$matches"
    fail "secret pattern scan — high-confidence matches found"
    ERRORS=$((ERRORS + 1))
else
    pass "secret pattern scan — no high-confidence matches"
fi
echo ""

# ── Step 1: cargo audit ───────────────────────────────────────────────────────
echo "--- cargo audit ---"
if ! command -v cargo-audit &>/dev/null; then
    warn "cargo-audit not installed. Run: cargo install cargo-audit"
    ERRORS=$((ERRORS + 1))
else
    if cargo audit; then
        pass "cargo audit — no vulnerabilities"
    else
        fail "cargo audit — advisories found"
        ERRORS=$((ERRORS + 1))
    fi
fi
echo ""

# ── Step 2: cargo deny ────────────────────────────────────────────────────────
echo "--- cargo deny check ---"
if ! command -v cargo-deny &>/dev/null; then
    warn "cargo-deny not installed. Run: cargo install cargo-deny"
    ERRORS=$((ERRORS + 1))
else
    if cargo deny check; then
        pass "cargo deny — advisories, licenses, bans, sources all ok"
    else
        fail "cargo deny — check failed"
        ERRORS=$((ERRORS + 1))
    fi
fi
echo ""

# ── Step 3: cargo vet ────────────────────────────────────────────────────────
echo "--- cargo vet ---"
if ! command -v cargo-vet &>/dev/null; then
    warn "cargo-vet not installed. Run: cargo install cargo-vet"
    ERRORS=$((ERRORS + 1))
else
    if cargo vet; then
        pass "cargo vet — all dependencies vetted"
    else
        fail "cargo vet — unvetted dependencies found"
        ERRORS=$((ERRORS + 1))
    fi
fi
echo ""

# ── Step 4: OSV Scanner ─────────────────────────────────────────────────────
echo "--- OSV Scanner ---"
if ! command -v osv-scanner &>/dev/null; then
    warn "osv-scanner not installed. Install OSV Scanner v2.3.6 from https://github.com/google/osv-scanner/releases/tag/v2.3.6"
    ERRORS=$((ERRORS + 1))
else
    if osv-scanner scan source -r .; then
        pass "OSV Scanner — no unaccepted dependency vulnerabilities"
    else
        fail "OSV Scanner — unaccepted dependency vulnerabilities found"
        ERRORS=$((ERRORS + 1))
    fi
fi
echo ""

# ── Step 5: cargo geiger (advisory) ──────────────────────────────────────────
# Surfaces transitive `unsafe` usage in the dependency tree. SunLit source is
# forbid(unsafe_code), so this measures what deps bring in. Advisory: failure
# does not count toward ERRORS. JSON artifact is the audit evidence.
#
# cargo-geiger requires a root package (it cannot consume a virtual manifest).
# We use secure_reference_service because it depends on every library crate
# and is the closest analogue to a downstream consumer's BOM.
#
# See docs/dev-guide/unsafe-budget.md.
echo "--- cargo geiger (advisory) ---"
if ! command -v cargo-geiger &>/dev/null; then
    warn "cargo-geiger not installed. Run: cargo install --locked cargo-geiger --version 0.13.0"
else
    mkdir -p output
    if (cd crates/secure_reference_service && cargo geiger \
        --all-features \
        --output-format Json \
        --update-readme=false \
        > "$WORKSPACE_ROOT/output/cargo-geiger.json"); then
        pass "cargo geiger — JSON artifact written to output/cargo-geiger.json"
    else
        warn "cargo geiger — non-zero exit (advisory); see output/cargo-geiger.json for details"
    fi
fi
echo ""

# ── Summary ──────────────────────────────────────────────────────────────────
echo "=== Audit Summary ==="
if [ "$ERRORS" -eq 0 ]; then
    pass "All supply-chain checks passed."
    exit 0
else
    fail "$ERRORS check(s) failed."
    exit 1
fi
