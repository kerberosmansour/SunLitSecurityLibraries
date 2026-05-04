#!/usr/bin/env bash
# scripts/dastardly_scan.sh — Run Dastardly (Burp Suite) DAST scan against secure_smoke_service
#
# Prerequisites:
#   - Docker installed and running
#   - Rust toolchain (cargo) available
#
# Usage:
#   bash scripts/dastardly_scan.sh [--no-build] [--keep-service]
#
# Options:
#   --no-build       Skip cargo build (use existing binary)
#   --keep-service   Don't stop the smoke service after scan
#
# Outputs:
#   output/dastardly-report.xml  — JUnit XML report
#
# Exit codes:
#   0 — No issues found (or info only)
#   1 — Issues detected or scan error

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$WORKSPACE_ROOT"

# ── Configuration ────────────────────────────────────────────────────────────
SMOKE_HOST="127.0.0.1"
SMOKE_PORT="3001"
SMOKE_URL="http://${SMOKE_HOST}:${SMOKE_PORT}"
DASTARDLY_IMAGE="public.ecr.aws/portswigger/dastardly:latest"
REPORT_DIR="output"
DASTARDLY_REPORT="${REPORT_DIR}/dastardly-report.xml"

# Docker networking: Dastardly runs inside a container and needs to
# reach the host service. On macOS/Windows host.docker.internal works
# by default. On Linux we need --add-host.
if [[ "$(uname)" == "Linux" ]]; then
    DOCKER_HOST_FLAG="--add-host=host.docker.internal:host-gateway"
else
    DOCKER_HOST_FLAG=""
fi
DASTARDLY_TARGET="http://host.docker.internal:${SMOKE_PORT}/dast-index"

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }
info() { echo -e "[INFO] $*"; }

# ── Parse arguments ──────────────────────────────────────────────────────────
SKIP_BUILD=false
KEEP_SERVICE=false
for arg in "$@"; do
    case "$arg" in
        --no-build)     SKIP_BUILD=true ;;
        --keep-service) KEEP_SERVICE=true ;;
        *) fail "Unknown argument: $arg"; exit 1 ;;
    esac
done

# ── Cleanup function ────────────────────────────────────────────────────────
SMOKE_PID=""
cleanup() {
    if [[ -n "$SMOKE_PID" ]] && [[ "$KEEP_SERVICE" == "false" ]]; then
        info "Stopping smoke service (PID $SMOKE_PID)..."
        kill "$SMOKE_PID" 2>/dev/null || true
        wait "$SMOKE_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# ── Preflight checks ────────────────────────────────────────────────────────
echo "=== Dastardly (Burp Suite) DAST Scan ==="
echo "Workspace: $WORKSPACE_ROOT"
echo ""

info "Checking prerequisites..."

if ! command -v docker &>/dev/null; then
    fail "Docker is not installed or not in PATH."
    echo "  Install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! docker info &>/dev/null 2>&1; then
    fail "Docker daemon is not running."
    echo "  Start Docker Desktop or the Docker daemon."
    exit 1
fi

if ! command -v cargo &>/dev/null; then
    fail "cargo is not installed or not in PATH."
    exit 1
fi

pass "All prerequisites met."
echo ""

# ── Step 1: Build the smoke service ─────────────────────────────────────────
if [[ "$SKIP_BUILD" == "false" ]]; then
    info "Building secure_smoke_service..."
    cargo build -p secure_smoke_service 2>&1
    pass "Build succeeded."
else
    info "Skipping build (--no-build)."
fi
echo ""

# ── Step 2: Start the smoke service ─────────────────────────────────────────
info "Starting secure_smoke_service on ${SMOKE_URL}..."

# Check if port is already in use
if lsof -i ":${SMOKE_PORT}" &>/dev/null 2>&1 || ss -tlnp 2>/dev/null | grep -q ":${SMOKE_PORT}" 2>/dev/null; then
    warn "Port ${SMOKE_PORT} is already in use. Assuming smoke service is already running."
    SMOKE_PID=""
else
    cargo run -p secure_smoke_service &
    SMOKE_PID=$!

    # Wait for service to be ready
    MAX_WAIT=30
    WAITED=0
    while ! curl -sf "${SMOKE_URL}/health" &>/dev/null; do
        sleep 1
        WAITED=$((WAITED + 1))
        if [[ $WAITED -ge $MAX_WAIT ]]; then
            fail "Smoke service did not start within ${MAX_WAIT} seconds."
            exit 1
        fi
    done
fi

pass "Smoke service is healthy at ${SMOKE_URL}."
echo ""

# ── Step 3: Prepare output directory ────────────────────────────────────────
mkdir -p "$REPORT_DIR"

# Remove stale report so we can detect generation failure
rm -f "$DASTARDLY_REPORT"

# ── Step 4: Pull Dastardly image ────────────────────────────────────────────
info "Pulling Dastardly Docker image (if not cached)..."
docker pull "$DASTARDLY_IMAGE" 2>&1 | tail -1
echo ""

# ── Step 5: Run Dastardly scan ──────────────────────────────────────────────
info "Running Dastardly scan..."
echo "  Target: ${DASTARDLY_TARGET}"
echo "  Report: ${DASTARDLY_REPORT}"
echo ""

# Dastardly scans the target URL and produces a JUnit XML report.
# It checks for: XSS (reflected & stored), SQL injection, OS command injection,
# path traversal, SSRF, XXE, and improper input handling.
# Exit code: 0 = clean, non-zero = findings.
DAST_EXIT_CODE=0
docker run --rm \
    $DOCKER_HOST_FLAG \
    --user "$(id -u)" \
    -v "${WORKSPACE_ROOT}/${REPORT_DIR}:/output:rw" \
    -e BURP_START_URL="${DASTARDLY_TARGET}" \
    -e BURP_REPORT_FILE_PATH="/output/dastardly-report.xml" \
    "$DASTARDLY_IMAGE" \
    2>&1 || DAST_EXIT_CODE=$?

echo ""

# ── Step 6: Check results ──────────────────────────────────────────────────
if [[ ! -f "$DASTARDLY_REPORT" ]]; then
    fail "Dastardly report not generated at ${DASTARDLY_REPORT}"
    echo "  Dastardly exit code: ${DAST_EXIT_CODE}"
    exit 1
fi

pass "Dastardly report generated: ${DASTARDLY_REPORT}"
echo ""

# Parse JUnit XML for failures (portable — no GNU grep -P required)
# Dastardly JUnit: <testsuites failures="F" ... tests="N">
FAILURES=$(sed -n 's/.*<testsuites[^>]* failures="\([0-9]*\)".*/\1/p' "$DASTARDLY_REPORT" | head -1)
FAILURES="${FAILURES:-0}"
TOTAL=$(sed -n 's/.*<testsuites[^>]* tests="\([0-9]*\)".*/\1/p' "$DASTARDLY_REPORT" | head -1)
TOTAL="${TOTAL:-0}"

echo "=== Dastardly Scan Summary ==="
echo "  Total checks:  ${TOTAL}"
echo "  Failures:      ${FAILURES}"
echo "  Dastardly exit code: ${DAST_EXIT_CODE}"
echo ""

# Dastardly exit code is the authoritative gate:
#   0 = no LOW/MEDIUM/HIGH findings (Info-only is acceptable)
#   non-zero = actionable findings detected
if [[ "$DAST_EXIT_CODE" -eq 0 ]]; then
    if [[ "$FAILURES" -gt 0 ]]; then
        warn "Dastardly reported ${FAILURES} Info-level issue(s) (not gate-blocking)."
        info "Reported items:"
        sed -n 's/.*<testcase name="\([^"]*\)".*/  - \1/p' "$DASTARDLY_REPORT" | grep -v 'No issues'
    fi
    pass "No actionable findings. Dastardly DAST gate passed."
    exit 0
else
    fail "Dastardly found ${FAILURES} issue(s). Review: ${DASTARDLY_REPORT}"
    # Print failing test names for quick triage
    echo ""
    info "Failing checks:"
    sed -n 's/.*<testcase name="\([^"]*\)".*/  - \1/p' "$DASTARDLY_REPORT" | grep -v 'No issues'
    exit 1
fi
