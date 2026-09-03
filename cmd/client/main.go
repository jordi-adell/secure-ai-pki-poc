package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
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
	serverURL := getEnv("SERVER_URL", "https://server:8443")
	interval := getEnvDuration("POLL_INTERVAL", 5*time.Second)

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
		GetClientCertificate: rc.GetClientCertificate,
		RootCAs:              caPool,
		MinVersion:           tls.VersionTLS13,
	}

	transport := &http.Transport{TLSClientConfig: tlsCfg}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}

	log.Printf("client polling %s every %s", serverURL, interval)
	for {
		if err := poll(client, serverURL); err != nil {
			log.Printf("poll error: %v", err)
		}
		time.Sleep(interval)
	}
}

func poll(client *http.Client, url string) error {
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var result map[string]string
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	log.Printf("response: status=%s client_cn=%s", result["status"], result["client_cn"])
	return nil
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

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}
