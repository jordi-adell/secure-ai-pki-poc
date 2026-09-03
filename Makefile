.DEFAULT_GOAL := help

CLUSTER_NAME        := pki-poc
KIND_CONTEXT        := kind-$(CLUSTER_NAME)
CERT_MANAGER_VERSION := v1.16.2
SERVER_IMAGE        := pki-poc/server:latest
CLIENT_IMAGE        := pki-poc/client:latest

GREEN  := \033[0;32m
RED    := \033[0;31m
CYAN   := \033[0;36m
YELLOW := \033[1;33m
NC     := \033[0m

.PHONY: all demo install-deps check-prereqs cluster install-cert-manager deploy-pki \
        deploy-layer1 validate-layer1 \
        build-images load-images \
        deploy-layer2 validate-layer2 \
        deploy-layer3 validate-layer3 \
        status test clean help

## ── Dependencies ─────────────────────────────────────────────────────────────

install-deps:
	@bash scripts/install-deps.sh

## ── Prerequisites check ──────────────────────────────────────────────────────

check-prereqs:
	@missing=""; \
	for tool in kind kubectl helm docker openssl; do \
	  command -v $$tool >/dev/null 2>&1 || missing="$$missing $$tool"; \
	done; \
	if [ -n "$$missing" ]; then \
	  printf "$(RED)✘ Missing required tools:$$missing$(NC)\n"; \
	  printf "  kind    → go install sigs.k8s.io/kind@latest\n"; \
	  printf "  kubectl → https://kubernetes.io/docs/tasks/tools/\n"; \
	  printf "  helm    → brew install helm  /  https://helm.sh/docs/intro/install/\n"; \
	  printf "  docker  → https://docs.docker.com/get-docker/\n"; \
	  printf "  openssl → pre-installed on most systems\n"; \
	  exit 1; \
	fi
	@printf "$(GREEN)✔ All prerequisites present$(NC)\n"

## ── Cluster ──────────────────────────────────────────────────────────────────

cluster: check-prereqs
	@if kind get clusters 2>/dev/null | grep -q "^$(CLUSTER_NAME)$$"; then \
	  printf "$(YELLOW)– Cluster '$(CLUSTER_NAME)' already exists, skipping$(NC)\n"; \
	else \
	  printf "$(CYAN)▶ Creating kind cluster '$(CLUSTER_NAME)'...$(NC)\n"; \
	  kind create cluster --name $(CLUSTER_NAME); \
	  printf "$(GREEN)✔ Cluster ready$(NC)\n"; \
	fi

## ── cert-manager ─────────────────────────────────────────────────────────────

install-cert-manager:
	@printf "$(CYAN)▶ Installing cert-manager $(CERT_MANAGER_VERSION)...$(NC)\n"
	helm repo add jetstack https://charts.jetstack.io --force-update
	helm upgrade --install cert-manager jetstack/cert-manager \
	  --namespace cert-manager --create-namespace \
	  --version $(CERT_MANAGER_VERSION) \
	  --values k8s/cert-manager/values.yaml \
	  --wait
	@printf "$(GREEN)✔ cert-manager ready$(NC)\n"

## ── PKI hierarchy ────────────────────────────────────────────────────────────

deploy-pki: install-cert-manager
	@printf "$(CYAN)▶ Deploying PKI CA hierarchy...$(NC)\n"
	kubectl apply -f k8s/pki/ --context $(KIND_CONTEXT)
	@printf "$(YELLOW)  Waiting for root CA certificate...$(NC)\n"
	kubectl wait --for=condition=Ready certificate/root-ca \
	  -n cert-manager --timeout=60s
	@printf "$(YELLOW)  Waiting for intermediate CA certificate...$(NC)\n"
	kubectl wait --for=condition=Ready certificate/intermediate-ca \
	  -n cert-manager --timeout=60s
	@printf "$(GREEN)✔ PKI CA hierarchy ready$(NC)\n"

## ── Layer 1 ──────────────────────────────────────────────────────────────────

deploy-layer1: deploy-pki
	@printf "$(CYAN)▶ Deploying Layer 1 (certificate issuance)...$(NC)\n"
	kubectl apply -f k8s/layer1/ --context $(KIND_CONTEXT)
	@printf "$(GREEN)✔ Layer 1 deployed$(NC)\n"

validate-layer1:
	@printf "$(CYAN)▶ Validating Layer 1...$(NC)\n"
	bash scripts/validate-layer1.sh

## ── Container images ─────────────────────────────────────────────────────────

build-images:
	@printf "$(CYAN)▶ Building server image...$(NC)\n"
	docker build -f services/server/Dockerfile -t $(SERVER_IMAGE) .
	@printf "$(CYAN)▶ Building client image...$(NC)\n"
	docker build -f services/client/Dockerfile -t $(CLIENT_IMAGE) .
	@printf "$(GREEN)✔ Images built$(NC)\n"

load-images: build-images
	@printf "$(CYAN)▶ Loading images into kind cluster...$(NC)\n"
	kind load docker-image $(SERVER_IMAGE) --name $(CLUSTER_NAME)
	kind load docker-image $(CLIENT_IMAGE) --name $(CLUSTER_NAME)
	@printf "$(GREEN)✔ Images loaded$(NC)\n"

## ── Layer 2 ──────────────────────────────────────────────────────────────────

deploy-layer2: deploy-pki load-images
	@printf "$(CYAN)▶ Deploying Layer 2 (mTLS services)...$(NC)\n"
	kubectl apply -f k8s/layer2/ --context $(KIND_CONTEXT) -R
	@printf "$(GREEN)✔ Layer 2 deployed$(NC)\n"

validate-layer2:
	@printf "$(CYAN)▶ Validating Layer 2...$(NC)\n"
	bash scripts/validate-layer2.sh

## ── Layer 3 ──────────────────────────────────────────────────────────────────

deploy-layer3: deploy-pki load-images
	@printf "$(CYAN)▶ Deploying Layer 3 (automatic rotation, 1h cert lifetime)...$(NC)\n"
	kubectl apply -f k8s/layer3/ --context $(KIND_CONTEXT) -R
	@printf "$(GREEN)✔ Layer 3 deployed$(NC)\n"

validate-layer3:
	@printf "$(CYAN)▶ Validating Layer 3 (cert rotation — waits up to 45 min)...$(NC)\n"
	bash scripts/validate-layer3.sh

## ── PKI status ───────────────────────────────────────────────────────────────

status:
	@bash scripts/pki-status.sh

## ── Tests ────────────────────────────────────────────────────────────────────

test:
	@printf "$(CYAN)▶ Running Go tests...$(NC)\n"
	go test ./... -v
	@printf "$(GREEN)✔ All tests pass$(NC)\n"

## ── Full demo ────────────────────────────────────────────────────────────────

demo: cluster install-cert-manager
	@printf "\n$(CYAN)════════════════════════════════════════════════════$(NC)\n"
	@printf "$(CYAN)  PKI PoC — Full Demo$(NC)\n"
	@printf "$(CYAN)════════════════════════════════════════════════════$(NC)\n\n"
	@$(MAKE) deploy-pki
	@printf "\n$(CYAN)── Layer 1: Certificate Issuance ──$(NC)\n"
	@$(MAKE) deploy-layer1
	@$(MAKE) validate-layer1
	@printf "\n$(CYAN)── Layer 2: mTLS Between Services ──$(NC)\n"
	@$(MAKE) deploy-layer2
	@$(MAKE) validate-layer2
	@printf "\n$(CYAN)── Layer 3: Automatic Rotation ──$(NC)\n"
	@$(MAKE) deploy-layer3
	@$(MAKE) validate-layer3
	@printf "\n$(GREEN)════════════════════════════════════════════════════$(NC)\n"
	@printf "$(GREEN)  All layers complete.$(NC)\n"
	@printf "$(GREEN)════════════════════════════════════════════════════$(NC)\n\n"

all: demo

## ── Cleanup ──────────────────────────────────────────────────────────────────

clean:
	@printf "$(CYAN)▶ Deleting kind cluster '$(CLUSTER_NAME)'...$(NC)\n"
	kind delete cluster --name $(CLUSTER_NAME)
	@printf "$(GREEN)✔ Cluster deleted$(NC)\n"

## ── Help ─────────────────────────────────────────────────────────────────────

help:
	@printf "$(CYAN)PKI PoC — Available targets:$(NC)\n"
	@printf "  install-deps          Install kind, helm, kubectl (macOS: brew; Linux: ~/.local/bin)\n"
	@printf "  cluster               Create kind cluster\n"
	@printf "  install-cert-manager  Install cert-manager via Helm\n"
	@printf "  deploy-pki            Deploy Root CA + Intermediate CA\n"
	@printf "  deploy-layer1         Deploy Layer 1 test certificate\n"
	@printf "  validate-layer1       Validate cert chain and SANs\n"
	@printf "  build-images          Build server + client Docker images\n"
	@printf "  load-images           Load images into kind\n"
	@printf "  deploy-layer2         Deploy mTLS server + client\n"
	@printf "  validate-layer2       Validate mTLS acceptance and rejection\n"
	@printf "  deploy-layer3         Deploy rotation demo (1h cert lifetime)\n"
	@printf "  validate-layer3       Wait for and confirm rotation\n"
	@printf "  status                Live PKI state — certs, issuers, deployments\n"
	@printf "  test                  Run Go unit tests\n"
	@printf "  demo / all            Full end-to-end demo\n"
	@printf "  clean                 Delete kind cluster\n"
