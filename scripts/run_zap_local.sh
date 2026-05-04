#!/usr/bin/env bash
# Temporary helper to run ZAP scan without shell escaping issues
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."
mkdir -p output

# Generate JWT
JWT_HEADER=$(echo -n '{"alg":"HS256","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_')
JWT_EXP=$(date -v+1H +%s)
JWT_PAYLOAD=$(echo -n "{\"sub\":\"zap-scanner\",\"iss\":\"smoke-test-issuer\",\"aud\":\"smoke-test-audience\",\"exp\":${JWT_EXP},\"roles\":[\"admin\"],\"tenant_id\":\"tenant-a\"}" | base64 | tr -d '=' | tr '+/' '-_')
SMOKE_JWT_SECRET="smoke-test-secret-key-min-32-bytes!!"
JWT_SIGNATURE=$(echo -n "${JWT_HEADER}.${JWT_PAYLOAD}" | openssl dgst -sha256 -hmac "$SMOKE_JWT_SECRET" -binary | base64 | tr -d '=' | tr '+/' '-_')
ZAP_JWT="${JWT_HEADER}.${JWT_PAYLOAD}.${JWT_SIGNATURE}"

echo "JWT: ${ZAP_JWT}"
echo ""

# Create a modified OpenAPI spec with host.docker.internal for Docker networking
sed 's|http://127.0.0.1:3001|http://host.docker.internal:3001|g' \
  crates/secure_smoke_service/openapi.yaml > output/openapi-docker.yaml

echo "Running ZAP API scan..."

docker run --rm \
  -v "$PWD/output:/zap/wrk/output:rw" \
  -v "$PWD/scripts/zap-rules.tsv:/zap/wrk/zap-rules.tsv:ro" \
  -v "$PWD/scripts/zap_hooks.py:/zap/wrk/zap_hooks.py:ro" \
  ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py \
  -t /zap/wrk/output/openapi-docker.yaml \
  -f openapi \
  -r output/zap-report.html \
  -J output/zap-report.json \
  -T 300 \
  -I \
  -c /zap/wrk/zap-rules.tsv \
  --hook /zap/wrk/zap_hooks.py \
  -z "-config replacer.full_list(0).description=AuthHeader -config replacer.full_list(0).enabled=true -config replacer.full_list(0).matchtype=REQ_HEADER -config replacer.full_list(0).matchstr=Authorization -config replacer.full_list(0).regex=false -config replacer.full_list(0).replacement=Bearer%20${ZAP_JWT} -config scanner.antiCSRF.enabled=false"

echo ""
echo "ZAP scan complete. Exit code: $?"
