#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=pki-lib.sh
source "$SCRIPT_DIR/pki-lib.sh"

NS=pki-layer3
SERVER_HOST=server.pki-layer3.svc.cluster.local
SERVER_PORT=8443
LOCAL_PORT=18444
MAX_WAIT_MINUTES=45
RENEW_BEFORE_SECONDS=1800  # 30m

banner "Layer 3 — Automatic Certificate Rotation"
info "Cert duration: 1h, renewBefore: 30m → rotation expected ~30m after issuance"

info "Waiting for Layer 3 deployments to be ready..."
kubectl wait deployment/server -n "$NS" --for=condition=Available --timeout=120s
kubectl wait deployment/client -n "$NS" --for=condition=Available --timeout=120s
pass "Layer 3 deployments ready"

ROOT_PEM=$(cert_pem_from_secret root-ca-tls cert-manager)
INTER_PEM=$(cert_pem_from_secret intermediate-ca-tls cert-manager)
SERVER_PEM=$(cert_pem_from_secret server-tls "$NS")

show_chain_banner "$ROOT_PEM" "$INTER_PEM" "$SERVER_PEM" "server.pki-layer3.svc.cluster.local"

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

get_server_pem() {
  kubectl get secret server-tls -n "$NS" -o jsonpath='{.data.tls\.crt}' | base64 -d
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

expiry_epoch() {
  local pem=$1
  local expiry_str
  expiry_str=$(cert_expiry "$pem")
  date -d "$expiry_str" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$expiry_str" +%s 2>/dev/null
}

CURRENT_PEM=$(get_server_pem)
SERIAL1=$(cert_serial "$CURRENT_PEM")
EXPIRY1=$(cert_expiry "$CURRENT_PEM")
EXPIRY1_EPOCH=$(expiry_epoch "$CURRENT_PEM")
RENEW_EPOCH=$(( EXPIRY1_EPOCH - RENEW_BEFORE_SECONDS ))

info "Initial serial : $SERIAL1"
info "Initial expiry : $EXPIRY1"

RENEW_TIME=$(date -d "@$RENEW_EPOCH" 2>/dev/null || date -r "$RENEW_EPOCH" 2>/dev/null)
info "Expected rotation at or after: $RENEW_TIME"
echo ""

for i in $(seq 1 $MAX_WAIT_MINUTES); do
  sleep 60

  if check_liveness; then
    LIVENESS_STATUS="${GREEN}alive${NC}"
  else
    fail "Service became unavailable at t=${i}m — downtime during rotation!"
  fi

  CURRENT_PEM=$(get_server_pem)
  SERIAL2=$(cert_serial "$CURRENT_PEM")
  EXPIRY2=$(cert_expiry "$CURRENT_PEM")

  NOW_EPOCH=$(date +%s)
  SECS_TO_RENEW=$(( RENEW_EPOCH - NOW_EPOCH ))
  if [ "$SECS_TO_RENEW" -gt 0 ]; then
    COUNTDOWN="(renewal in ${SECS_TO_RENEW}s)"
  else
    COUNTDOWN="(renewal window open)"
  fi

  waiting "t=${i}m — service=$(echo -e $LIVENESS_STATUS) serial=${SERIAL2} ${DIM}${COUNTDOWN}${NC}"

  if [ "$SERIAL1" != "$SERIAL2" ]; then
    show_rotation_event "$i" "$SERIAL1" "$EXPIRY1" "$SERIAL2" "$EXPIRY2"
    pass "Rotation verified — new cert signed by same CA:"
    if verify_chain "$ROOT_PEM" "$INTER_PEM" "$CURRENT_PEM"; then
      pass "Chain verification on rotated cert: root → intermediate → leaf OK"
    else
      fail "Chain verification failed on rotated cert"
    fi
    echo ""
    pass "Layer 3 complete — zero-downtime automatic rotation confirmed."
    exit 0
  fi
done

fail "No rotation observed in ${MAX_WAIT_MINUTES} minutes. Check cert-manager logs."
