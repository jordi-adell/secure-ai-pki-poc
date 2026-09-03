#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=pki-lib.sh
source "$SCRIPT_DIR/pki-lib.sh"

banner "Layer 1 — Certificate Issuance"

info "Applying Layer 1 manifests..."
kubectl apply -f k8s/layer1/

info "Waiting for test-workload certificate to be ready (60s timeout)..."
kubectl wait \
  --for=condition=Ready \
  certificate/test-workload \
  -n pki-layer1 \
  --timeout=60s

pass "Certificate test-workload is Ready"

ROOT_PEM=$(cert_pem_from_secret root-ca-tls cert-manager)
INTER_PEM=$(cert_pem_from_secret intermediate-ca-tls cert-manager)
LEAF_PEM=$(cert_pem_from_secret test-workload-tls pki-layer1)

show_chain_banner "$ROOT_PEM" "$INTER_PEM" "$LEAF_PEM" "test-workload.pki-layer1.svc.cluster.local"

info "Verifying cryptographic chain: root → intermediate → leaf..."
if verify_chain "$ROOT_PEM" "$INTER_PEM" "$LEAF_PEM"; then
  pass "Chain verification: root → intermediate → leaf OK"
else
  fail "Chain verification failed"
fi

info "Checking leaf issuer matches intermediate CA..."
if cert_issuer_cn "$LEAF_PEM" | grep -q "pki-poc-intermediate-ca"; then
  pass "Leaf is signed by Intermediate CA"
else
  fail "Leaf issuer mismatch: $(cert_issuer_cn "$LEAF_PEM")"
fi

info "Checking Subject Alternative Names..."
SANS=$(cert_sans "$LEAF_PEM")
if echo "$SANS" | grep -q "test-workload"; then
  pass "SANs: $SANS"
else
  fail "SAN missing expected DNS name. Got: $SANS"
fi

echo ""
pass "Layer 1 complete — PKI can issue valid certificates."
