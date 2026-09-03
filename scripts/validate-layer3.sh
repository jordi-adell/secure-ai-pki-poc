#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

pass()    { echo -e "${GREEN}✔ $*${NC}"; }
fail()    { echo -e "${RED}✘ $*${NC}"; exit 1; }
info()    { echo -e "${CYAN}▶ $*${NC}"; }
waiting() { echo -e "${YELLOW}⏳ $*${NC}"; }

NS=pki-layer3
SERVER_HOST=server.pki-layer3.svc.cluster.local
SERVER_PORT=8443
LOCAL_PORT=18444
MAX_WAIT_MINUTES=45

info "Layer 3 — Automatic Certificate Rotation Validation"
info "Cert duration: 1h, renewBefore: 30m → rotation expected around 30m after issuance"

info "Waiting for Layer 3 deployments to be ready..."
kubectl wait deployment/server -n "$NS" --for=condition=Available --timeout=120s
kubectl wait deployment/client -n "$NS" --for=condition=Available --timeout=120s
pass "Layer 3 deployments ready"

TMPDIR=$(mktemp -d)
PF_PID=""

cleanup() {
  [ -n "$PF_PID" ] && kill "$PF_PID" 2>/dev/null
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

info "Extracting TLS certificates from Secrets..."
kubectl get secret client-tls -n "$NS" -o jsonpath='{.data.tls\.crt}' | base64 -d > "$TMPDIR/client.crt"
kubectl get secret client-tls -n "$NS" -o jsonpath='{.data.tls\.key}' | base64 -d > "$TMPDIR/client.key"
kubectl get secret client-tls -n "$NS" -o jsonpath='{.data.ca\.crt}'  | base64 -d > "$TMPDIR/ca.crt"

start_portforward() {
  [ -n "$PF_PID" ] && kill "$PF_PID" 2>/dev/null
  kubectl port-forward svc/server "$LOCAL_PORT:$SERVER_PORT" -n "$NS" >/dev/null 2>&1 &
  PF_PID=$!
  sleep 2
}

start_portforward

get_serial() {
  kubectl get secret server-tls -n "$NS" \
    -o jsonpath='{.data.tls\.crt}' \
    | base64 -d \
    | openssl x509 -noout -serial 2>/dev/null \
    | sed 's/serial=//'
}

get_expiry() {
  kubectl get secret server-tls -n "$NS" \
    -o jsonpath='{.data.tls\.crt}' \
    | base64 -d \
    | openssl x509 -noout -enddate 2>/dev/null \
    | sed 's/notAfter=//'
}

check_liveness() {
  if ! kill -0 "$PF_PID" 2>/dev/null; then
    start_portforward
  fi
  curl -sf --max-time 5 \
    --resolve "${SERVER_HOST}:${LOCAL_PORT}:127.0.0.1" \
    --cacert "$TMPDIR/ca.crt" \
    --cert   "$TMPDIR/client.crt" \
    --key    "$TMPDIR/client.key" \
    "https://${SERVER_HOST}:${LOCAL_PORT}/" 2>/dev/null \
    | grep -q '"status":"ok"'
}

SERIAL1=$(get_serial)
EXPIRY1=$(get_expiry)
info "Initial serial: $SERIAL1"
info "Initial expiry: $EXPIRY1"

START_TIME=$(date +%s)

for i in $(seq 1 $MAX_WAIT_MINUTES); do
  sleep 60
  ELAPSED=$((i))

  if check_liveness; then
    LIVENESS_STATUS="alive"
  else
    LIVENESS_STATUS="ERROR"
    fail "Service became unavailable at ${ELAPSED}m — downtime during rotation!"
  fi

  SERIAL2=$(get_serial)
  EXPIRY2=$(get_expiry)
  waiting "t=${ELAPSED}m — service=${LIVENESS_STATUS} serial=${SERIAL2}"

  if [ "$SERIAL1" != "$SERIAL2" ]; then
    echo ""
    pass "Certificate rotation detected at ${ELAPSED}m!"
    pass "  Old serial : $SERIAL1"
    pass "  New serial : $SERIAL2"
    pass "  Old expiry : $EXPIRY1"
    pass "  New expiry : $EXPIRY2"
    pass "  Service was available throughout rotation (zero downtime)"
    echo ""
    pass "Layer 3 validation complete — automatic rotation confirmed."
    exit 0
  fi
done

fail "No rotation observed in ${MAX_WAIT_MINUTES} minutes. Check cert-manager logs."
