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
SERVER_HOST=server.pki-layer2.svc.cluster.local
SERVER_PORT=8443
LOCAL_PORT=18443

info "Layer 2 — mTLS Validation"

info "Waiting for server deployment to be ready..."
kubectl wait deployment/server -n "$NS" --for=condition=Available --timeout=120s
pass "Server deployment ready"

info "Waiting for client deployment to be ready..."
kubectl wait deployment/client -n "$NS" --for=condition=Available --timeout=120s
pass "Client deployment ready"

info "Extracting TLS certificates from Secrets..."
TMPDIR=$(mktemp -d)
trap 'kill "$PF_PID" 2>/dev/null; rm -rf "$TMPDIR"' EXIT

kubectl get secret client-tls -n "$NS" -o jsonpath='{.data.tls\.crt}' | base64 -d > "$TMPDIR/client.crt"
kubectl get secret client-tls -n "$NS" -o jsonpath='{.data.tls\.key}' | base64 -d > "$TMPDIR/client.key"
kubectl get secret client-tls -n "$NS" -o jsonpath='{.data.ca\.crt}'  | base64 -d > "$TMPDIR/ca.crt"

info "Starting port-forward to server service (localhost:$LOCAL_PORT)..."
kubectl port-forward svc/server "$LOCAL_PORT:$SERVER_PORT" -n "$NS" >/dev/null 2>&1 &
PF_PID=$!
sleep 2

CURL_BASE="curl -sf --max-time 5
  --resolve ${SERVER_HOST}:${LOCAL_PORT}:127.0.0.1
  --cacert $TMPDIR/ca.crt"

info "Test 1: Valid mTLS connection (should succeed with HTTP 200)..."
RESPONSE=$(${CURL_BASE} \
  --cert "$TMPDIR/client.crt" \
  --key  "$TMPDIR/client.key" \
  "https://${SERVER_HOST}:${LOCAL_PORT}/")

if echo "$RESPONSE" | grep -q '"status":"ok"'; then
  pass "Valid mTLS accepted — $(echo "$RESPONSE" | tr -d '\n')"
else
  fail "Valid mTLS failed. Response: $RESPONSE"
fi

info "Test 2: Connection without client cert (should be rejected)..."
if ${CURL_BASE} "https://${SERVER_HOST}:${LOCAL_PORT}/" 2>/dev/null; then
  fail "Expected TLS rejection but server returned a response"
else
  pass "Connection without client cert was rejected (TLS error as expected)"
fi

info "Checking client pod logs for successful mTLS polls..."
LOGS=$(kubectl logs -n "$NS" deployment/client --tail=20 2>/dev/null || true)
if echo "$LOGS" | grep -q 'status=ok'; then
  pass "Client logs confirm mTLS polls are succeeding"
else
  info "Client log output:"
  echo "$LOGS"
  fail "Client logs do not show successful responses yet"
fi

echo ""
pass "Layer 2 validation complete — mTLS enforced, unauthorized connections rejected."
