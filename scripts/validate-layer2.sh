#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

pass() { echo -e "${GREEN}✔ $*${NC}"; }
fail() { echo -e "${RED}✘ $*${NC}"; exit 1; }
info() { echo -e "${CYAN}▶ $*${NC}"; }

NS=pki-layer2
SERVER_URL=https://server.pki-layer2.svc.cluster.local:8443

info "Layer 2 — mTLS Validation"

info "Waiting for server deployment to be ready..."
kubectl wait deployment/server -n "$NS" --for=condition=Available --timeout=120s
pass "Server deployment ready"

info "Waiting for client deployment to be ready..."
kubectl wait deployment/client -n "$NS" --for=condition=Available --timeout=120s
pass "Client deployment ready"

CLIENT_POD=$(kubectl get pod -n "$NS" -l app=client -o jsonpath='{.items[0].metadata.name}')

info "Test 1: Valid mTLS connection (should succeed)..."
HTTP_CODE=$(kubectl exec -n "$NS" "$CLIENT_POD" -- \
  wget -qO- \
  --certificate=/certs/tls.crt \
  --private-key=/certs/tls.key \
  --ca-certificate=/certs/ca.crt \
  "$SERVER_URL" 2>&1 || true)

if echo "$HTTP_CODE" | grep -q '"status":"ok"'; then
  pass "Valid mTLS connection accepted — response: $HTTP_CODE"
else
  fail "Valid mTLS connection failed. Response: $HTTP_CODE"
fi

info "Test 2: Connection without client cert (should be rejected)..."
REJECT_OUTPUT=$(kubectl exec -n "$NS" "$CLIENT_POD" -- \
  wget -qO- \
  --ca-certificate=/certs/ca.crt \
  "$SERVER_URL" 2>&1 || true)

if echo "$REJECT_OUTPUT" | grep -qiE "ssl|tls|certificate|error|failed"; then
  pass "Connection without client cert was rejected (TLS error as expected)"
else
  fail "Expected TLS rejection but got: $REJECT_OUTPUT"
fi

info "Test 3: Check client logs show successful mTLS polls..."
LOGS=$(kubectl logs -n "$NS" deployment/client --tail=10)
if echo "$LOGS" | grep -q '"status":"ok"'; then
  pass "Client logs confirm mTLS polls are succeeding"
else
  info "Client log output:"
  echo "$LOGS"
  fail "Client logs do not show successful responses"
fi

echo ""
pass "Layer 2 validation complete — mTLS enforced, unauthorized connections rejected."
