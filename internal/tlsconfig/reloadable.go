package tlsconfig

import (
	"crypto/tls"
	"os"
	"sync"
	"time"
)

type ReloadableCert struct {
	mu       sync.RWMutex
	cert     *tls.Certificate
	certFile string
	keyFile  string
	modTime  time.Time
}

func New(certFile, keyFile string) (*ReloadableCert, error) {
	rc := &ReloadableCert{certFile: certFile, keyFile: keyFile}
	if err := rc.load(); err != nil {
		return nil, err
	}
	return rc, nil
}

func (r *ReloadableCert) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert, nil
}

func (r *ReloadableCert) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert, nil
}

func (r *ReloadableCert) Reload() error {
	info, err := os.Stat(r.certFile)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !info.ModTime().After(r.modTime) {
		return nil
	}
	return r.loadLocked()
}

func (r *ReloadableCert) Watch(interval time.Duration) chan struct{} {
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				info, err := os.Stat(r.certFile)
				if err != nil {
					continue
				}
				r.mu.Lock()
				if info.ModTime().After(r.modTime) {
					_ = r.loadLocked()
				}
				r.mu.Unlock()
			}
		}
	}()
	return stop
}

func (r *ReloadableCert) load() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.loadLocked()
}

func (r *ReloadableCert) loadLocked() error {
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return err
	}
	info, err := os.Stat(r.certFile)
	if err != nil {
		return err
	}
	r.cert = &cert
	r.modTime = info.ModTime()
	return nil
}
