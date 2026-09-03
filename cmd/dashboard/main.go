package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
	_ "embed"
)

//go:embed index.html
var indexHTML string

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

func main() {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = defaultAddr
	}
	go poll()
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/status", handleStatus)
	http.HandleFunc("/api/logs", handleLogs)
	log.Printf("PKI Dashboard → http://localhost%s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
