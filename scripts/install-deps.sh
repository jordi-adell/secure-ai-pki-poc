#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "${GREEN}✔ $*${NC}"; }
info() { echo -e "${CYAN}▶ $*${NC}"; }
skip() { echo -e "${YELLOW}– $* already installed, skipping${NC}"; }

KIND_VERSION=v0.23.0
HELM_VERSION=v3.16.2
KUBECTL_VERSION=v1.31.0

OS=$(uname -s)
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  ARCH_KIND=amd64; ARCH_KUBECTL=amd64 ;;
  arm64|aarch64) ARCH_KIND=arm64; ARCH_KUBECTL=arm64 ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

install_macos() {
  if ! command -v brew >/dev/null 2>&1; then
    echo "Homebrew not found. Install it from https://brew.sh then re-run."
    exit 1
  fi

  if ! command -v kind >/dev/null 2>&1; then
    info "Installing kind via Homebrew..."
    brew install kind
    ok "kind installed"
  else
    skip "kind"
  fi

  if ! command -v helm >/dev/null 2>&1; then
    info "Installing helm via Homebrew..."
    brew install helm
    ok "helm installed"
  else
    skip "helm"
  fi

  if ! command -v kubectl >/dev/null 2>&1; then
    info "Installing kubectl via Homebrew..."
    brew install kubectl
    ok "kubectl installed"
  else
    skip "kubectl"
  fi
}

install_linux() {
  INSTALL_DIR="${HOME}/.local/bin"
  mkdir -p "$INSTALL_DIR"

  if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
    echo -e "${YELLOW}  Note: add $INSTALL_DIR to your PATH (e.g. export PATH=\"\$HOME/.local/bin:\$PATH\")${NC}"
  fi

  if ! command -v kind >/dev/null 2>&1; then
    info "Installing kind ${KIND_VERSION}..."
    curl -sSL "https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-${ARCH_KIND}" \
      -o "$INSTALL_DIR/kind"
    chmod +x "$INSTALL_DIR/kind"
    ok "kind ${KIND_VERSION} installed to $INSTALL_DIR/kind"
  else
    skip "kind"
  fi

  if ! command -v helm >/dev/null 2>&1; then
    info "Installing helm ${HELM_VERSION}..."
    HELM_TMP=$(mktemp -d)
    trap 'rm -rf "$HELM_TMP"' EXIT
    curl -sSL "https://get.helm.sh/helm-${HELM_VERSION}-linux-${ARCH_KIND}.tar.gz" \
      -o "$HELM_TMP/helm.tar.gz"
    tar -xzf "$HELM_TMP/helm.tar.gz" -C "$HELM_TMP"
    mv "$HELM_TMP/linux-${ARCH_KIND}/helm" "$INSTALL_DIR/helm"
    chmod +x "$INSTALL_DIR/helm"
    ok "helm ${HELM_VERSION} installed to $INSTALL_DIR/helm"
  else
    skip "helm"
  fi

  if ! command -v kubectl >/dev/null 2>&1; then
    info "Installing kubectl ${KUBECTL_VERSION}..."
    curl -sSL "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${ARCH_KUBECTL}/kubectl" \
      -o "$INSTALL_DIR/kubectl"
    chmod +x "$INSTALL_DIR/kubectl"
    ok "kubectl ${KUBECTL_VERSION} installed to $INSTALL_DIR/kubectl"
  else
    skip "kubectl"
  fi
}

echo ""
info "Installing missing dependencies for pki-poc..."
echo ""

case "$OS" in
  Darwin) install_macos ;;
  Linux)  install_linux ;;
  *)      echo "Unsupported OS: $OS"; exit 1 ;;
esac

echo ""
ok "Done. Run 'make check-prereqs' to verify."
