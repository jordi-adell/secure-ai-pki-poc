# Development Reference

Technical internals, repository layout, and operational details for the PKI PoC.

---

## Repository Layout

```
.
├── Makefile                         # all automation targets
├── cmd/
│   └── dashboard/
│       ├── main.go                  # Go HTTP server: /api/status, /api/logs (SSE), /report
│       ├── index.html               # PKI live dashboard (dark SPA, polls /api/status)
│       └── report.html              # Printable HTML report (Go html/template)
├── internal/
│   └── tlsconfig/
│       ├── reloadable.go            # ReloadableCert: hot-reload via per-handshake callbacks
│       └── reloadable_test.go       # unit + integration tests (TDD)
├── services/
│   ├── server/
│   │   ├── Dockerfile               # multi-stage: golang:alpine → distroless/static
│   │   └── main.go                  # mTLS HTTPS server
│   └── client/
│       ├── Dockerfile
│       └── main.go                  # mTLS client polling server every 5s
├── k8s/
│   ├── cert-manager/values.yaml     # Helm values (installCRDs: true)
│   ├── pki/                         # CA hierarchy (applied in order 00→05)
│   │   ├── 00-namespace.yaml
│   │   ├── 01-root-ca.yaml          # SelfSigned bootstrap ClusterIssuer + root CA cert
│   │   ├── 02-root-ca-issuer.yaml   # ClusterIssuer backed by root CA secret
│   │   ├── 03-intermediate-ca.yaml  # Intermediate CA cert (isCA: true)
│   │   ├── 04-intermediate-issuer.yaml
│   │   └── 05-workload-issuer.yaml  # ClusterIssuer used by all leaf certs
│   ├── layer1/                      # test Certificate (24h lifetime)
│   ├── layer2/                      # server + client deployments (24h certs)
│   ├── layer3/                      # server + client deployments (1h certs)
│   └── dashboard/
│       └── admin-user.yaml          # ServiceAccount + ClusterRoleBinding for K8s Dashboard
├── scripts/
│   ├── pki-lib.sh                   # shared bash library (cert parsing, chain banners)
│   ├── validate-layer1.sh
│   ├── validate-layer2.sh
│   ├── validate-layer3.sh
│   └── pki-status.sh                # make status — live PKI overview
└── .github/
    └── workflows/ci.yml
```

---

## Go Services

### mTLS Server (`services/server/main.go`)

- Listens on `:8443` (TLS)
- `tls.Config.ClientAuth = tls.RequireAndVerifyClientCert`
- `tls.Config.GetCertificate` → `ReloadableCert.GetCertificate` (per-handshake callback)
- `GET /` returns `{"status":"ok","client_cn":"<subject CN>"}`

### mTLS Client (`services/client/main.go`)

- Polls `https://server.<ns>.svc.cluster.local/` every 5s
- `tls.Config.GetClientCertificate` → `ReloadableCert.GetClientCertificate`
- Logs each response with the server cert serial: `status=ok serial=<hex>`

### ReloadableCert (`internal/tlsconfig/reloadable.go`)

Hot-reload without pod restart:

```
┌─────────────────────────────────────────────────┐
│  ReloadableCert                                 │
│  ┌─────────────┐   sync.RWMutex                │
│  │ tls.Cert    │◄──── Load() / Reload()        │
│  └─────────────┘                               │
│        ▲                                        │
│  watchAndReload goroutine                       │
│  polls cert file mtime every 30s               │
│  → calls Reload() on change                    │
└─────────────────────────────────────────────────┘
         │
         ▼  called per TLS handshake by crypto/tls
  GetCertificate(*tls.ClientHelloInfo) → *tls.Certificate
  GetClientCertificate(*tls.CertificateRequestInfo) → *tls.Certificate
```

cert-manager updates the Kubernetes Secret when it renews a cert. The Secret is
volume-mounted as files. The file watcher detects the `mtime` change and reloads
under a write lock. New connections immediately use the rotated cert; in-flight
connections complete with the old cert.

### Dockerfiles

Multi-stage build: `golang:1.25-alpine` (builder) → `gcr.io/distroless/static:nonroot`
(runtime). The final image has no shell, no package manager, and runs as a non-root user.
Validation scripts test from outside the cluster via `kubectl port-forward` rather than
`kubectl exec` because distroless containers have no shell utilities.

---

## Validation Scripts

All scripts source `scripts/pki-lib.sh` which provides:

| Function | Purpose |
|----------|---------|
| `cert_pem_from_secret secret ns [key]` | Extracts and base64-decodes a cert from a K8s Secret using `--template='{{index .data "key"}}'` (handles dotted key names like `tls.crt`) |
| `cert_cn / cert_serial / cert_expiry / cert_issuer_cn / cert_sans` | openssl field extractors; all end with `\|\| true` so `set -eo pipefail` doesn't kill display-only calls |
| `show_chain_banner root inter leaf label` | Prints the full Root → Intermediate → Leaf tree with cert details |
| `verify_chain root inter leaf` | Runs `openssl verify` and returns the exit code — callers branch on it |
| `show_rotation_event elapsed old new` | Green rotation banner with old/new serial + expiry |

### Layer 2 validation (mTLS)

Tests from the host using `kubectl port-forward` + `curl --resolve`:

```bash
kubectl port-forward svc/server "$LOCAL_PORT:$SERVER_PORT" -n pki-layer2 &
curl --resolve "${SERVER_HOST}:${LOCAL_PORT}:127.0.0.1" \
     --cacert <(root+inter bundle) --cert <(client cert) --key <(client key) \
     "https://${SERVER_HOST}:${LOCAL_PORT}/"
```

`--resolve` makes curl use the port-forward address while still sending the correct
TLS SNI hostname, so the server-side SAN validation passes.

### Layer 3 validation (rotation)

Watches for a serial change on a 60-second poll loop (up to 45 min). On change:

1. Calls `show_rotation_event` with old/new serial and expiry
2. Re-runs `verify_chain` with the new cert to confirm the chain is still valid
3. Exits 0

---

## PKI Dashboard (`cmd/dashboard/`)

A stdlib-only Go HTTP server with three endpoints:

| Endpoint | Description |
|----------|-------------|
| `GET /` | Dark-themed SPA — cert chain tree, inventory table, deployment health, rotation events, streaming logs |
| `GET /api/status` | JSON snapshot polled every 10s by the frontend |
| `GET /api/logs?ns=&deploy=` | Server-Sent Events stream of `kubectl logs -f` output |
| `GET /report` | Printable HTML report rendered server-side via `html/template` |

A background goroutine polls kubectl every 10s behind a `sync.RWMutex`. It detects
rotations by comparing the cert serial against the previous poll. `//go:embed` bundles
`index.html` and `report.html` into the binary at build time.

---

## Layer 1 — Inspect Manually

```bash
kubectl get secret test-workload-tls -n pki-layer1 \
  -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -text -noout

kubectl get certificate -A
kubectl get clusterissuer
```

## Layer 2 — Inspect Manually

```bash
kubectl logs -f deployment/client -n pki-layer2
kubectl logs -f deployment/server -n pki-layer2
```

## Layer 3 — Inspect Manually

```bash
kubectl get secret server-tls -n pki-layer3 \
  -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -serial -dates
```

---

## CI Pipeline (`.github/workflows/ci.yml`)

Two parallel jobs:

| Job | Steps | Timeout |
|-----|-------|---------|
| **PKI Demo** | kind cluster via `helm/kind-action`, `make demo-ci` (layers 1–3, no rotation wait) | 20 min |
| **Dashboard Smoke Test** | `go build`, start server, poll `/api/status` for valid JSON shape, check `/report` renders | 5 min |

`make demo-ci` uses `validate-layer3-ci` instead of `validate-layer3` — it only waits
for the cert to reach `Ready` state, not for a serial change.

---

## Make Targets

```
make help                 # full target list
make cluster              # create kind cluster
make install-cert-manager # install cert-manager via Helm
make deploy-pki           # Root CA + Intermediate CA
make deploy-layer1        # Layer 1 cert
make validate-layer1      # verify chain + SANs
make build-images         # build server + client Docker images
make load-images          # load images into kind
make deploy-layer2        # mTLS services (24h certs)
make validate-layer2      # mTLS accept/reject test
make deploy-layer3        # rotation services (1h certs)
make validate-layer3      # wait for rotation (up to 45 min)
make validate-layer3-ci   # CI-safe: verify cert issuance only
make demo                 # full demo including rotation wait
make demo-ci              # CI demo without rotation wait
make dashboards           # start PKI + K8s dashboards (Ctrl+C stops both)
make dashboard            # PKI dashboard only (http://localhost:8080)
make k8s-dashboard        # install + port-forward K8s Dashboard (https://localhost:8443)
make k8s-dashboard-token  # print a fresh K8s Dashboard login token
make status               # terminal PKI overview
make test                 # go test ./...
make clean                # delete kind cluster
```
