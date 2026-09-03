#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=pki-lib.sh
source "$SCRIPT_DIR/pki-lib.sh"

NS=pki-layer2
SERVER_HOST=server.pki-layer2.svc.cluster.local
SERVER_PORT=8443
LOCAL_PORT=18443

banner "Layer 2 — mTLS Between Services"

info "Waiting for server deployment to be ready..."
kubectl wait deployment/server -n "$NS" --for=condition=Available --timeout=120s
pass "Server deployment ready"

info "Waiting for client deployment to be ready..."
kubectl wait deployment/client -n "$NS" --for=condition=Available --timeout=120s
pass "Client deployment ready"

ROOT_PEM=$(cert_pem_from_secret root-ca-tls cert-manager)
INTER_PEM=$(cert_pem_from_secret intermediate-ca-tls cert-manager)
SERVER_PEM=$(cert_pem_from_secret server-tls "$NS")
CLIENT_PEM=$(cert_pem_from_secret client-tls "$NS")

show_chain_banner "$ROOT_PEM" "$INTER_PEM" "$SERVER_PEM" "server.pki-layer2.svc.cluster.local"

info "Client certificate:"
divider
print_cert_block "  " "" "$CLIENT_PEM"
divider
echo ""

TMPDIR=$(mktemp -d)
PF_PID=""
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
  pass "mTLS accepted — server returned: $RESPONSE"
else
  fail "Valid mTLS failed. Response: $RESPONSE"
fi

info "Test 2: Connection without client cert (should be rejected)..."
if ${CURL_BASE} "https://${SERVER_HOST}:${LOCAL_PORT}/" 2>/dev/null; then
  fail "Expected TLS rejection but server returned a response"
else
  pass "No-cert connection rejected (TLS error as expected)"
fi

info "Checking client pod logs for successful mTLS polls..."
LOGS=$(kubectl logs -n "$NS" deployment/client --tail=20 2>/dev/null || true)
if echo "$LOGS" | grep -q 'status=ok'; then
  pass "Client polls succeeding — last log entries:"
  echo "$LOGS" | tail -3 | while IFS= read -r line; do
    printf "    ${DIM}%s${NC}\n" "$line"
  done
else
  info "Client log output:"
  echo "$LOGS"
  fail "Client logs do not show successful responses yet"
fi

echo ""
pass "Layer 2 complete — mTLS enforced, unauthorized connections rejected."
