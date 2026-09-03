# PKI System for mTLS in Kubernetes

A proof-of-concept PKI system deployed on Kubernetes using [cert-manager](https://cert-manager.io/).
Demonstrates three progressive layers: certificate issuance, mutual TLS between services, and
automatic certificate rotation.

## PKI Concepts

| Term | What it means here |
|------|--------------------|
| **Trust anchor** | Root CA certificate. The root CA key never signs workload certs. |
| **Certificate chain** | Root CA → Intermediate CA → Leaf cert. Verifying a leaf cert traces up to the root. |
| **SAN** | Subject Alternative Name. DNS names in the cert that TLS clients verify against. |
| **mTLS** | Mutual TLS: both server and client present certificates. The server rejects clients without a valid cert signed by the trusted CA. |
| **Rotation** | cert-manager renews a cert before it expires (`renewBefore`) and updates the Kubernetes Secret in place. Services hot-reload the new cert without restarting. |

## PKI Hierarchy

```
Root CA  (trust anchor, 10-year lifetime)
  └── Intermediate CA  (operational CA, 5-year lifetime)
        ├── test-workload cert   — Layer 1
        ├── server cert          — Layer 2 / 3
        └── client cert          — Layer 2 / 3
```

All CA secrets live in the `cert-manager` namespace, accessible to `ClusterIssuer` resources
cluster-wide.

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Docker | ≥ 24 | [docs.docker.com](https://docs.docker.com/get-docker/) |
| kind | ≥ 0.23 | `go install sigs.k8s.io/kind@latest` |
| kubectl | ≥ 1.28 | [kubernetes.io](https://kubernetes.io/docs/tasks/tools/) |
| Helm | ≥ 3.14 | `brew install helm` |
| openssl | any | pre-installed on most systems |

## Quick Start — Full Demo

```bash
make demo
```

This creates the kind cluster, installs cert-manager, deploys all three layers, and runs
validation for each. Layer 3 validation waits up to 45 minutes for cert rotation.

Run individual steps with `make help`.

---

## Layer 1 — Certificate Issuance

### What it does

Deploys the two-tier PKI (Root CA → Intermediate CA → leaf certs) and issues a test
certificate to a workload in the `pki-layer1` namespace.

### Deploy

```bash
make deploy-pki
make deploy-layer1
```

### Validate

```bash
make validate-layer1
```

The script:
1. Waits for the `test-workload` Certificate to be `Ready`
2. Prints the leaf cert's Subject, SANs, validity, and Issuer
3. Verifies the full chain: `root → intermediate → leaf` using `openssl verify`
4. Confirms the leaf issuer is the Intermediate CA (not the Root CA)

### Inspect manually

```bash
# Show the issued certificate
kubectl get secret test-workload-tls -n pki-layer1 \
  -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -text -noout

# Show all cert-manager Certificate resources
kubectl get certificate -A
```

---

## Layer 2 — mTLS Between Services

### What it does

Deploys a Go HTTPS server and a Go client in the `pki-layer2` namespace. Both hold
certificates issued by the PKI. The server requires and validates a client certificate
(`tls.RequireAndVerifyClientCert`). Connections without a valid certificate are rejected.

### Deploy

```bash
make deploy-layer2
```

### Validate

```bash
make validate-layer2
```

The script:
1. Confirms the server accepts a connection with a valid client cert (HTTP 200)
2. Confirms the server rejects a connection without a client cert (TLS error)

### Inspect manually

```bash
# Follow client logs (shows successful mTLS polls)
kubectl logs -f deployment/client -n pki-layer2

# See server logs
kubectl logs -f deployment/server -n pki-layer2
```

---

## Layer 3 — Automatic Certificate Rotation

### What it does

Same services as Layer 2, deployed in `pki-layer3`, but with short cert lifetimes:
`duration: 1h`, `renewBefore: 30m`. cert-manager renews the cert ~30 minutes after issuance.
The Go services watch the cert files and hot-reload the new cert on every new TLS handshake —
no pod restart, no dropped connections.

### Deploy

```bash
make deploy-layer3
```

### Validate

```bash
make validate-layer3
```

The script polls every 60 seconds (up to 45 minutes) and:
1. Checks the server's cert serial number changes (rotation confirmed)
2. Curl-tests the server every poll cycle to prove it stays available throughout
3. Reports old vs new serial number and updated expiry

### How hot-reload works

cert-manager updates the Kubernetes Secret when it renews a cert. The Secret is
volume-mounted in the pod. The Go `ReloadableCert` type runs a background goroutine
that polls the cert file's `mtime` every 30 s. On change, it loads the new
`tls.Certificate` under a write lock.

The TLS server and client use `tls.Config.GetCertificate` and
`tls.Config.GetClientCertificate` callbacks respectively — Go invokes these
**per-handshake** (not once at startup), so new connections immediately use the
rotated cert while existing connections complete normally.

---

## Repository Structure

```
.
├── Makefile                    # all automation targets
├── cmd/
│   ├── server/main.go          # mTLS server binary
│   └── client/main.go          # mTLS client binary
├── internal/
│   └── tlsconfig/
│       ├── reloadable.go       # ReloadableCert: hot-reload via callbacks
│       └── reloadable_test.go  # unit + integration tests
├── services/
│   ├── server/Dockerfile       # multi-stage: golang:alpine → distroless
│   └── client/Dockerfile
├── k8s/
│   ├── cert-manager/           # Helm values
│   ├── pki/                    # CA hierarchy (applied in order 00→03)
│   ├── layer1/                 # test Certificate CRD
│   ├── layer2/                 # server + client (24h certs)
│   └── layer3/                 # server + client (1h certs for rotation demo)
└── scripts/
    ├── validate-layer1.sh      # cert chain + SAN verification
    ├── validate-layer2.sh      # mTLS accept/reject
    └── validate-layer3.sh      # rotation detection + liveness
```

## Running Tests

```bash
make test
# or directly:
go test ./... -v
```

Tests cover:
- `ReloadableCert` initial load, manual reload, and automatic watch-based reload
- mTLS handshake: valid client cert accepted, missing client cert rejected
