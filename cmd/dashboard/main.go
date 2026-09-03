package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
	_ "embed"
)

//go:embed index.html
var indexHTML string

//go:embed report.html
var reportTmplSrc string

var reportTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"formatTime": func(t time.Time) string {
		return t.UTC().Format("2006-01-02 15:04:05 UTC")
	},
	"formatExpiry": func(s string) string {
		if s == "" {
			return "—"
		}
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return s
		}
		return t.UTC().Format("2006-01-02 15:04:05 UTC")
	},
}).Parse(reportTmplSrc))

const defaultAddr = ":8080"

var pkiNamespaces = map[string]bool{
	"pki-layer1": true,
	"pki-layer2": true,
	"pki-layer3": true,
}

type certList struct {
	Items []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Spec struct {
			SecretName string `json:"secretName"`
			IssuerRef  struct {
				Name string `json:"name"`
			} `json:"issuerRef"`
		} `json:"spec"`
		Status struct {
			Conditions []struct {
				Type   string `json:"type"`
				Status string `json:"status"`
			} `json:"conditions"`
			NotAfter string `json:"notAfter"`
		} `json:"status"`
	} `json:"items"`
}

type deployList struct {
	Items []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Status struct {
			ReadyReplicas int32 `json:"readyReplicas"`
			Replicas      int32 `json:"replicas"`
		} `json:"status"`
	} `json:"items"`
}

type CertInfo struct {
	Namespace string   `json:"namespace"`
	Name      string   `json:"name"`
	Ready     bool     `json:"ready"`
	Issuer    string   `json:"issuer"`
	Expiry    string   `json:"expiry"`
	Serial    string   `json:"serial"`
	Subject   string   `json:"subject"`
	SANs      []string `json:"sans"`
}

type DeployInfo struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Ready     int32  `json:"ready"`
	Total     int32  `json:"total"`
}

type RotationEvent struct {
	Namespace  string    `json:"namespace"`
	CertName   string    `json:"cert_name"`
	OldSerial  string    `json:"old_serial"`
	NewSerial  string    `json:"new_serial"`
	OldExpiry  string    `json:"old_expiry"`
	NewExpiry  string    `json:"new_expiry"`
	DetectedAt time.Time `json:"detected_at"`
}

type Status struct {
	Certs       []CertInfo      `json:"certs"`
	Deployments []DeployInfo    `json:"deployments"`
	Rotations   []RotationEvent `json:"rotations"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

type certState struct {
	serial string
	expiry string
}

var (
	mu      sync.RWMutex
	current Status
	known   = map[string]certState{}
	events  []RotationEvent
)

func kubectl(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "kubectl", args...).Output()
}

func pipe(script string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "bash", "-c", script).Output()
}

func secretCertDetails(secret, ns string) (serial, subject string, sans []string) {
	script := fmt.Sprintf(
		`kubectl get secret %s -n %s --template='{{index .data "tls.crt"}}' 2>/dev/null `+
			`| base64 -d | openssl x509 -noout -subject -serial -ext subjectAltName 2>/dev/null`,
		secret, ns,
	)
	out, err := pipe(script)
	if err != nil || len(out) == 0 {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "serial="):
			serial = strings.TrimPrefix(line, "serial=")
		case strings.HasPrefix(line, "subject="):
			for _, part := range strings.Split(strings.TrimPrefix(line, "subject="), ",") {
				part = strings.TrimSpace(part)
				if after, ok := strings.CutPrefix(part, "CN"); ok {
					subject = strings.TrimSpace(strings.TrimLeft(after, " ="))
				}
			}
		case strings.Contains(line, "DNS:") || strings.Contains(line, "IP:"):
			for _, entry := range strings.Split(line, ",") {
				entry = strings.TrimSpace(entry)
				if strings.HasPrefix(entry, "DNS:") || strings.HasPrefix(entry, "IP:") {
					sans = append(sans, entry)
				}
			}
		}
	}
	return
}

func fetchCerts() []CertInfo {
	raw, err := kubectl("get", "certificates", "--all-namespaces", "-o", "json")
	if err != nil {
		log.Printf("kubectl get certificates: %v", err)
		return nil
	}
	var list certList
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil
	}
	result := make([]CertInfo, 0, len(list.Items))
	for _, item := range list.Items {
		ci := CertInfo{
			Namespace: item.Metadata.Namespace,
			Name:      item.Metadata.Name,
			Issuer:    item.Spec.IssuerRef.Name,
			Expiry:    item.Status.NotAfter,
		}
		for _, cond := range item.Status.Conditions {
			if cond.Type == "Ready" {
				ci.Ready = cond.Status == "True"
				break
			}
		}
		if item.Spec.SecretName != "" {
			ci.Serial, ci.Subject, ci.SANs = secretCertDetails(item.Spec.SecretName, item.Metadata.Namespace)
		}
		result = append(result, ci)
	}
	return result
}

func fetchDeployments() []DeployInfo {
	raw, err := kubectl("get", "deployments", "--all-namespaces", "-o", "json")
	if err != nil {
		log.Printf("kubectl get deployments: %v", err)
		return nil
	}
	var list deployList
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil
	}
	result := make([]DeployInfo, 0)
	for _, item := range list.Items {
		if !pkiNamespaces[item.Metadata.Namespace] {
			continue
		}
		result = append(result, DeployInfo{
			Namespace: item.Metadata.Namespace,
			Name:      item.Metadata.Name,
			Ready:     item.Status.ReadyReplicas,
			Total:     item.Status.Replicas,
		})
	}
	return result
}

func detectRotations(certs []CertInfo) {
	for _, c := range certs {
		if c.Serial == "" {
			continue
		}
		key := c.Namespace + "/" + c.Name
		prev, seen := known[key]
		if seen && prev.serial != "" && prev.serial != c.Serial {
			events = append(events, RotationEvent{
				Namespace:  c.Namespace,
				CertName:   c.Name,
				OldSerial:  prev.serial,
				NewSerial:  c.Serial,
				OldExpiry:  prev.expiry,
				NewExpiry:  c.Expiry,
				DetectedAt: time.Now(),
			})
			log.Printf("rotation detected: %s/%s %s → %s", c.Namespace, c.Name, prev.serial, c.Serial)
		}
		known[key] = certState{serial: c.Serial, expiry: c.Expiry}
	}
}

func poll() {
	for {
		certs := fetchCerts()
		deploys := fetchDeployments()

		mu.Lock()
		detectRotations(certs)
		current = Status{
			Certs:       certs,
			Deployments: deploys,
			Rotations:   events,
			UpdatedAt:   time.Now(),
		}
		mu.Unlock()

		time.Sleep(10 * time.Second)
	}
}

type treeRow struct {
	Class     string
	Prefix    string
	Name      string
	Namespace string
	Ready     bool
	Expiry    string
}

type reportData struct {
	GeneratedAt        string
	CertManagerVersion string
	TotalCerts         int
	ReadyCerts         int
	TotalDeploys       int
	ReadyDeploys       int
	Layers             int
	Tree               []treeRow
	Status             Status
}

func buildTree(certs []CertInfo) []treeRow {
	var rows []treeRow
	root := findCert(certs, "cert-manager", "root-ca")
	inter := findCert(certs, "cert-manager", "intermediate-ca")

	if root != nil {
		rows = append(rows, treeRow{"root", "◆", root.Name, "", root.Ready, fmtExpiry(root.Expiry)})
	}
	if inter != nil {
		rows = append(rows, treeRow{"inter", "└─◆", inter.Name, "", inter.Ready, fmtExpiry(inter.Expiry)})
	}

	var leaves []CertInfo
	for _, c := range certs {
		if c.Namespace != "cert-manager" {
			leaves = append(leaves, c)
		}
	}
	sort.Slice(leaves, func(i, j int) bool {
		if leaves[i].Namespace != leaves[j].Namespace {
			return leaves[i].Namespace < leaves[j].Namespace
		}
		return leaves[i].Name < leaves[j].Name
	})
	for i, c := range leaves {
		prefix := "├─◆"
		if i == len(leaves)-1 {
			prefix = "└─◆"
		}
		rows = append(rows, treeRow{"leaf", prefix, c.Name, c.Namespace, c.Ready, fmtExpiry(c.Expiry)})
	}
	return rows
}

func findCert(certs []CertInfo, ns, name string) *CertInfo {
	for i := range certs {
		if certs[i].Namespace == ns && certs[i].Name == name {
			return &certs[i]
		}
	}
	return nil
}

func fmtExpiry(s string) string {
	if s == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	return t.UTC().Format("2006-01-02")
}

func activeLayers(certs []CertInfo) int {
	ns := map[string]bool{}
	for _, c := range certs {
		if c.Namespace != "cert-manager" {
			ns[c.Namespace] = true
		}
	}
	return len(ns)
}

func handleReport(w http.ResponseWriter, _ *http.Request) {
	mu.RLock()
	s := current
	mu.RUnlock()

	readyCerts := 0
	for _, c := range s.Certs {
		if c.Ready {
			readyCerts++
		}
	}
	readyDeploys := 0
	for _, d := range s.Deployments {
		if d.Ready == d.Total && d.Total > 0 {
			readyDeploys++
		}
	}

	data := reportData{
		GeneratedAt:        time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		CertManagerVersion: "v1.16.2",
		TotalCerts:         len(s.Certs),
		ReadyCerts:         readyCerts,
		TotalDeploys:       len(s.Deployments),
		ReadyDeploys:       readyDeploys,
		Layers:             activeLayers(s.Certs),
		Tree:               buildTree(s.Certs),
		Status:             s,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := reportTmpl.Execute(w, data); err != nil {
		log.Printf("report template: %v", err)
	}
}

func handleStatus(w http.ResponseWriter, _ *http.Request) {
	mu.RLock()
	s := current
	mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s)
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	ns := r.URL.Query().Get("ns")
	deploy := r.URL.Query().Get("deploy")
	if ns == "" || deploy == "" {
		http.Error(w, "ns and deploy required", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	ctx := r.Context()
	cmd := exec.CommandContext(ctx, "kubectl", "logs", "-f", "--tail=80",
		"deployment/"+deploy, "-n", ns)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := cmd.Start(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			cmd.Process.Kill()
			return
		default:
		}
		fmt.Fprintf(w, "data: %s\n\n", scanner.Text())
		flusher.Flush()
	}
}

func handleIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, indexHTML)
}

func selfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "pki-dashboard"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
}

func main() {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = defaultAddr
	}

	cert, err := selfSignedCert()
	if err != nil {
		log.Fatalf("generate TLS cert: %v", err)
	}

	ln, err := tls.Listen("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	go poll()
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/report", handleReport)
	http.HandleFunc("/api/status", handleStatus)
	http.HandleFunc("/api/logs", handleLogs)
	log.Printf("PKI Dashboard → https://localhost%s  (self-signed cert — accept browser warning)", addr)
	log.Fatal(http.Serve(ln, nil))
}
