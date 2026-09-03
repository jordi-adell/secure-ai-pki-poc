#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

pass() { echo -e "${GREEN}✔ $*${NC}"; }
fail() { echo -e "${RED}✘ $*${NC}"; exit 1; }
info() { echo -e "${CYAN}▶ $*${NC}"; }

info "Layer 1 — Certificate Issuance Validation"

info "Applying Layer 1 manifests..."
kubectl apply -f k8s/layer1/

info "Waiting for test-workload certificate to be ready (60s timeout)..."
kubectl wait \
  --for=condition=Ready \
  certificate/test-workload \
  -n pki-layer1 \
  --timeout=60s

pass "Certificate test-workload is Ready"

info "Extracting leaf certificate from Secret..."
LEAF_PEM=$(kubectl get secret test-workload-tls -n pki-layer1 \
  -o jsonpath='{.data.tls\.crt}' | base64 -d)

info "Extracting intermediate CA cert..."
INTERMEDIATE_PEM=$(kubectl get secret intermediate-ca-tls -n cert-manager \
  -o jsonpath='{.data.tls\.crt}' | base64 -d)

info "Extracting root CA cert..."
ROOT_PEM=$(kubectl get secret root-ca-tls -n cert-manager \
  -o jsonpath='{.data.tls\.crt}' | base64 -d)

info "Certificate details:"
echo "$LEAF_PEM" | openssl x509 -text -noout | grep -E "Subject:|Issuer:|Not Before|Not After|DNS:"

info "Verifying full chain: root → intermediate → leaf..."
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "$ROOT_PEM" > "$TMPDIR/root.pem"
echo "$INTERMEDIATE_PEM" > "$TMPDIR/intermediate.pem"
echo "$LEAF_PEM" > "$TMPDIR/leaf.pem"

LEAF_ONLY=$(echo "$LEAF_PEM" | openssl x509 2>/dev/null)
echo "$LEAF_ONLY" > "$TMPDIR/leaf-only.pem"

if openssl verify \
  -CAfile "$TMPDIR/root.pem" \
  -untrusted "$TMPDIR/intermediate.pem" \
  "$TMPDIR/leaf-only.pem" > /dev/null 2>&1; then
  pass "Full chain verification: root → intermediate → leaf OK"
else
  fail "Full chain verification failed"
fi

info "Checking leaf issuer matches intermediate CA..."
LEAF_ISSUER=$(echo "$LEAF_PEM" | openssl x509 -noout -issuer | sed 's/issuer=//')
INTERMEDIATE_SUBJECT=$(echo "$INTERMEDIATE_PEM" | openssl x509 -noout -subject | sed 's/subject=//')
if echo "$LEAF_ISSUER" | grep -q "pki-poc-intermediate-ca"; then
  pass "Leaf cert issuer: $LEAF_ISSUER"
else
  fail "Leaf issuer mismatch. Got: $LEAF_ISSUER"
fi

info "Checking Subject Alternative Names..."
if echo "$LEAF_PEM" | openssl x509 -noout -ext subjectAltName | grep -q "test-workload"; then
  pass "SAN contains expected DNS name"
else
  fail "SAN missing expected DNS name"
fi

echo ""
pass "Layer 1 validation complete — PKI can issue valid certificates."
