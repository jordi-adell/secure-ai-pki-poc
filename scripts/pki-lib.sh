#!/usr/bin/env bash

GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

pass()    { echo -e "${GREEN}✔ $*${NC}"; }
fail()    { echo -e "${RED}✘ $*${NC}"; exit 1; }
info()    { echo -e "${CYAN}▶ $*${NC}"; }
waiting() { echo -e "${YELLOW}⏳ $*${NC}"; }
banner()  { echo -e "\n${CYAN}══════════════════════════════════════════════════════${NC}\n  ${BOLD}$*${NC}\n${CYAN}══════════════════════════════════════════════════════${NC}"; }
divider() { echo -e "${DIM}──────────────────────────────────────────────────────${NC}"; }

cert_pem_from_secret() {
  local secret=$1 ns=$2 key=${3:-tls.crt}
  kubectl get secret "$secret" -n "$ns" \
    --template="{{index .data \"${key}\"}}" 2>/dev/null | base64 -d
}

cert_field() {
  local pem=$1
  shift
  # shellcheck disable=SC2068
  echo "$pem" | openssl x509 -noout $@ 2>/dev/null || true
}

cert_cn() {
  local pem=$1
  cert_field "$pem" -subject | sed 's/.*CN\s*=\s*//' | sed 's/,.*//' || true
}

cert_serial() {
  local pem=$1
  cert_field "$pem" -serial | sed 's/serial=//' || true
}

cert_expiry() {
  local pem=$1
  cert_field "$pem" -enddate | sed 's/notAfter=//' || true
}

cert_start() {
  local pem=$1
  cert_field "$pem" -startdate | sed 's/notBefore=//' || true
}

cert_issuer_cn() {
  local pem=$1
  cert_field "$pem" -issuer | sed 's/.*CN\s*=\s*//' | sed 's/,.*//' || true
}

cert_sans() {
  local pem=$1
  cert_field "$pem" -ext subjectAltName \
    | grep -oE 'DNS:[^,]+|IP:[^,]+' | tr '\n' ' ' || true
}

print_cert_block() {
  local indent=$1 label=$2 pem=$3
  local cn serial expiry start issuer_cn sans
  cn=$(cert_cn "$pem")
  serial=$(cert_serial "$pem")
  expiry=$(cert_expiry "$pem")
  start=$(cert_start "$pem")
  issuer_cn=$(cert_issuer_cn "$pem")
  sans=$(cert_sans "$pem")

  printf "${indent}${BOLD}%-12s${NC} %s\n" "Subject:" "$cn"
  printf "${indent}${DIM}%-12s${NC} %s\n"  "Issuer:"   "$issuer_cn"
  printf "${indent}${DIM}%-12s${NC} %s\n"  "Serial:"   "$serial"
  printf "${indent}${DIM}%-12s${NC} %s\n"  "Valid:"    "$start"
  printf "${indent}${DIM}%-12s${NC} %s\n"  "Expires:"  "$expiry"
  if [ -n "$sans" ]; then
    printf "${indent}${DIM}%-12s${NC} %s\n" "SANs:" "$sans"
  fi
}

show_chain_banner() {
  local root_pem=$1 inter_pem=$2 leaf_pem=$3 leaf_label=${4:-"Leaf Certificate"}

  banner "PKI Trust Chain"
  echo ""
  printf "  ${GREEN}◆ Root CA${NC}\n"
  print_cert_block "    " "" "$root_pem"
  echo ""
  printf "  ${CYAN}└─◆ Intermediate CA${NC}\n"
  print_cert_block "      " "" "$inter_pem"
  echo ""
  printf "  ${YELLOW}  └─◆ ${leaf_label}${NC}\n"
  print_cert_block "        " "" "$leaf_pem"
  echo ""
  divider
}

verify_chain() {
  local root_pem=$1 inter_pem=$2 leaf_pem=$3 tmpdir
  tmpdir=$(mktemp -d)
  echo "$root_pem"  > "$tmpdir/root.pem"
  echo "$inter_pem" > "$tmpdir/inter.pem"
  echo "$leaf_pem" | openssl x509 2>/dev/null > "$tmpdir/leaf.pem"
  local rc=0
  openssl verify -CAfile "$tmpdir/root.pem" -untrusted "$tmpdir/inter.pem" \
    "$tmpdir/leaf.pem" > /dev/null 2>&1 || rc=$?
  rm -rf "$tmpdir"
  return $rc
}

show_rotation_event() {
  local elapsed=$1 old_serial=$2 old_expiry=$3 new_serial=$4 new_expiry=$5
  echo ""
  echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
  echo -e "  ${BOLD}${GREEN}🔄  Certificate Rotated at t=${elapsed}m${NC}"
  echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
  printf "  ${DIM}%-12s${NC} %s\n" "Old serial:" "$old_serial"
  printf "  ${DIM}%-12s${NC} %s\n" "Old expiry:" "$old_expiry"
  printf "  ${GREEN}%-12s${NC} %s\n" "New serial:" "$new_serial"
  printf "  ${GREEN}%-12s${NC} %s\n" "New expiry:" "$new_expiry"
  echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
  echo ""
}
