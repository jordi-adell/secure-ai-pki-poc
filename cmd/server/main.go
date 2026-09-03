package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jordi-adell/secure-ai-pki-poc/internal/tlsconfig"
)

func main() {
	certFile := getEnv("TLS_CERT_FILE", "/certs/tls.crt")
	keyFile := getEnv("TLS_KEY_FILE", "/certs/tls.key")
	caFile := getEnv("TLS_CA_FILE", "/certs/ca.crt")
	addr := getEnv("LISTEN_ADDR", ":8443")

	rc, err := tlsconfig.New(certFile, keyFile)
	if err != nil {
		log.Fatalf("load cert: %v", err)
	}
	stop := rc.Watch(30 * time.Second)
	defer close(stop)

	caPool, err := loadCACert(caFile)
	if err != nil {
		log.Fatalf("load CA: %v", err)
	}

	tlsCfg := &tls.Config{
		GetCertificate: rc.GetCertificate,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      caPool,
		MinVersion:     tls.VersionTLS13,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/healthz", handleHealthz)

	srv := &http.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: tlsCfg,
	}

	log.Printf("server listening on %s (mTLS)", addr)
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	clientCN := ""
	if len(r.TLS.PeerCertificates) > 0 {
		clientCN = r.TLS.PeerCertificates[0].Subject.CommonName
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":    "ok",
		"client_cn": clientCN,
	})
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func loadCACert(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	return pool, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
