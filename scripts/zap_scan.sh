#!/usr/bin/env bash
# scripts/zap_scan.sh — Run OWASP ZAP DAST scan against secure_smoke_service
#
# Prerequisites:
#   - Docker installed and running
#   - Rust toolchain (cargo) available
#   - python3 available (for report parsing)
#
# Usage:
#   bash scripts/zap_scan.sh [--no-build] [--keep-service]
#
# Options:
#   --no-build       Skip cargo build (use existing binary)
#   --keep-service   Don't stop the smoke service after scan
#
# Outputs:
#   output/zap-report.html   — Human-readable ZAP report
#   output/zap-report.json   — Machine-readable ZAP report (for CI gating)
#
# Exit codes:
#   0 — No high/critical findings
#   1 — High/critical findings detected or scan error

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$WORKSPACE_ROOT"

# ── Configuration ────────────────────────────────────────────────────────────
SMOKE_HOST="127.0.0.1"
SMOKE_PORT="3001"
SMOKE_URL="http://${SMOKE_HOST}:${SMOKE_PORT}"
OPENAPI_SPEC="crates/secure_smoke_service/openapi.yaml"
ZAP_IMAGE="ghcr.io/zaproxy/zaproxy:stable"
REPORT_DIR="output"
ZAP_RULES_FILE="scripts/zap-rules.tsv"
ZAP_REPORT_HTML="${REPORT_DIR}/zap-report.html"
ZAP_REPORT_JSON="${REPORT_DIR}/zap-report.json"
ZAP_CHECK_SCRIPT="scripts/zap_check.py"

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
echo "=== OWASP ZAP DAST Scan ==="
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

if ! command -v python3 &>/dev/null; then
    fail "python3 is not installed or not in PATH."
    exit 1
fi

if [[ ! -f "$OPENAPI_SPEC" ]]; then
    fail "OpenAPI spec not found: $OPENAPI_SPEC"
    exit 1
fi

if [[ ! -f "$ZAP_CHECK_SCRIPT" ]]; then
    fail "ZAP check script not found: $ZAP_CHECK_SCRIPT"
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

# ── Step 4: Generate a JWT for authenticated scanning ───────────────────────
# The smoke service uses HS256 JWT with a dev secret.
# We generate a valid token so ZAP can test authenticated routes.
info "Generating JWT for authenticated scanning..."

JWT_HEADER=$(echo -n '{"alg":"HS256","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_')
# Token valid for 1 hour from now
if [[ "$(uname)" == "Darwin" ]]; then
    JWT_EXP=$(date -v+1H +%s)
else
    JWT_EXP=$(date -d '+1 hour' +%s)
fi
JWT_PAYLOAD=$(echo -n "{\"sub\":\"zap-scanner\",\"iss\":\"smoke-test-issuer\",\"aud\":\"smoke-test-audience\",\"exp\":${JWT_EXP},\"roles\":[\"admin\"],\"tenant_id\":\"tenant-a\"}" | base64 | tr -d '=' | tr '+/' '-_')

# The smoke service uses this dev-only HS256 secret (from config.rs SecurityConfig::dev()).
# This is NOT a production secret — it is hard-coded for testing only.
SMOKE_JWT_SECRET="smoke-test-secret-key-min-32-bytes!!"
JWT_SIGNATURE=$(echo -n "${JWT_HEADER}.${JWT_PAYLOAD}" | openssl dgst -sha256 -hmac "$SMOKE_JWT_SECRET" -binary | base64 | tr -d '=' | tr '+/' '-_')
ZAP_JWT="${JWT_HEADER}.${JWT_PAYLOAD}.${JWT_SIGNATURE}"

pass "JWT generated for ZAP scanner."
echo ""

# ── Step 5: Run OWASP ZAP API scan ─────────────────────────────────────────
info "Pulling ZAP Docker image (if not cached)..."
docker pull "$ZAP_IMAGE" 2>&1 | tail -1

# Create a modified OpenAPI spec with host.docker.internal for Docker networking
# ZAP runs inside Docker and cannot reach 127.0.0.1 on the host.
info "Creating Docker-compatible OpenAPI spec..."
sed "s|http://127.0.0.1:${SMOKE_PORT}|http://host.docker.internal:${SMOKE_PORT}|g" \
    "${OPENAPI_SPEC}" > "${REPORT_DIR}/openapi-docker.yaml"

info "Running OWASP ZAP API scan..."
echo "  Target: http://host.docker.internal:${SMOKE_PORT}"
echo "  OpenAPI spec: ${OPENAPI_SPEC} (rewritten for Docker)"
echo ""

# Determine host gateway for Docker to reach host network
if [[ "$(uname)" == "Linux" ]]; then
    DOCKER_HOST_FLAG="--add-host=host.docker.internal:host-gateway"
else
    # macOS/Windows: host.docker.internal is available by default
    DOCKER_HOST_FLAG=""
fi

# Build ZAP command-line options
ZAP_OPTS=()

# Add rules file if it exists
if [[ -f "$ZAP_RULES_FILE" ]]; then
    ZAP_OPTS+=(-c "/zap/wrk/$(basename "$ZAP_RULES_FILE")")
fi

# Run the ZAP API scan
# -t target URL or OpenAPI spec URL
# -f openapi format
# -J json report name
# -r html report name
# -z additional ZAP options for authentication
ZAP_EXIT_CODE=0
docker run --rm \
    $DOCKER_HOST_FLAG \
    -v "${WORKSPACE_ROOT}/${REPORT_DIR}:/zap/wrk/output:rw" \
    -v "${WORKSPACE_ROOT}/scripts:/zap/wrk/scripts:ro" \
    ${ZAP_RULES_FILE:+-v "${WORKSPACE_ROOT}/${ZAP_RULES_FILE}:/zap/wrk/$(basename "$ZAP_RULES_FILE"):ro"} \
    "$ZAP_IMAGE" zap-api-scan.py \
    -t /zap/wrk/output/openapi-docker.yaml \
    -f openapi \
    -r output/zap-report.html \
    -J output/zap-report.json \
    -T 120 \
    --hook /zap/wrk/scripts/zap_hooks.py \
    -z "-config replacer.full_list\(0\).description=AuthHeader \
        -config replacer.full_list\(0\).enabled=true \
        -config replacer.full_list\(0\).matchtype=REQ_HEADER \
        -config replacer.full_list\(0\).matchstr=Authorization \
        -config replacer.full_list\(0\).regex=false \
        -config replacer.full_list\(0\).replacement=Bearer\ ${ZAP_JWT}" \
    "${ZAP_OPTS[@]}" \
    2>&1 || ZAP_EXIT_CODE=$?

echo ""

# ── Step 6: Check ZAP scan results ─────────────────────────────────────────
if [[ ! -f "${ZAP_REPORT_JSON}" ]]; then
    fail "ZAP JSON report not generated at ${ZAP_REPORT_JSON}"
    echo "  ZAP exit code: ${ZAP_EXIT_CODE}"
    exit 1
fi

pass "ZAP reports generated:"
echo "  HTML: ${ZAP_REPORT_HTML}"
echo "  JSON: ${ZAP_REPORT_JSON}"
echo ""

# ── Step 7: Parse report and gate on findings ───────────────────────────────
info "Checking for high/critical findings..."

BASELINE_ARG=""
if [[ -f "scripts/zap-baseline.json" ]]; then
    BASELINE_ARG="--baseline scripts/zap-baseline.json"
fi

CHECK_EXIT_CODE=0
python3 "$ZAP_CHECK_SCRIPT" \
    --report "${ZAP_REPORT_JSON}" \
    $BASELINE_ARG \
    2>&1 || CHECK_EXIT_CODE=$?

echo ""

# ── Summary ──────────────────────────────────────────────────────────────────
echo "=== ZAP Scan Summary ==="
if [[ $CHECK_EXIT_CODE -eq 0 ]]; then
    pass "No high/critical findings. DAST gate passed."
    exit 0
else
    fail "High/critical findings detected. DAST gate failed."
    echo "  Review: ${ZAP_REPORT_HTML}"
    exit 1
fi
