#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=pki-lib.sh
source "$SCRIPT_DIR/pki-lib.sh"

banner "PKI Status — $(date '+%Y-%m-%d %H:%M:%S')"

printf "\n${BOLD}Certificates (all namespaces)${NC}\n"
divider
kubectl get certificates --all-namespaces \
  --sort-by='.metadata.namespace' \
  -o custom-columns=\
'NAMESPACE:.metadata.namespace,NAME:.metadata.name,READY:.status.conditions[0].status,ISSUER:.spec.issuerRef.name,EXPIRY:.status.notAfter' \
  2>/dev/null || echo "  (none found or cert-manager not installed)"
echo ""

printf "${BOLD}Issuers & ClusterIssuers${NC}\n"
divider
echo -e "${DIM}ClusterIssuers:${NC}"
kubectl get clusterissuers -o custom-columns='NAME:.metadata.name,READY:.status.conditions[0].status' 2>/dev/null \
  | sed 's/^/  /' || echo "  (none)"
echo ""
for ns in cert-manager pki-layer1 pki-layer2 pki-layer3; do
  COUNT=$(kubectl get issuers -n "$ns" --no-headers 2>/dev/null | wc -l | tr -d ' ')
  if [ "$COUNT" -gt 0 ]; then
    echo -e "${DIM}Issuers in $ns:${NC}"
    kubectl get issuers -n "$ns" -o custom-columns='NAME:.metadata.name,READY:.status.conditions[0].status' 2>/dev/null \
      | sed 's/^/  /'
  fi
done
echo ""

printf "${BOLD}Workload Deployments${NC}\n"
divider
for ns in pki-layer2 pki-layer3; do
  EXISTS=$(kubectl get namespace "$ns" --no-headers 2>/dev/null | wc -l | tr -d ' ')
  if [ "$EXISTS" -gt 0 ]; then
    echo -e "${DIM}$ns:${NC}"
    kubectl get deployments -n "$ns" \
      -o custom-columns='NAME:.metadata.name,READY:.status.readyReplicas,AVAILABLE:.status.availableReplicas' \
      2>/dev/null | sed 's/^/  /'
    echo ""
  fi
done

printf "${BOLD}CA Certificate Details${NC}\n"
divider

ROOT_PEM=$(cert_pem_from_secret root-ca-tls cert-manager 2>/dev/null || true)
INTER_PEM=$(cert_pem_from_secret intermediate-ca-tls cert-manager 2>/dev/null || true)

if [ -n "$ROOT_PEM" ]; then
  printf "\n  ${GREEN}◆ Root CA${NC}\n"
  print_cert_block "    " "" "$ROOT_PEM"
fi

if [ -n "$INTER_PEM" ]; then
  printf "\n  ${CYAN}└─◆ Intermediate CA${NC}\n"
  print_cert_block "      " "" "$INTER_PEM"
fi

echo ""
divider
