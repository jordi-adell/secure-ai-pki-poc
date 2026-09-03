package tlsconfig_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/jordi-adell/secure-ai-pki-poc/internal/tlsconfig"
)

func TestNew_LoadsInitialCert(t *testing.T) {
	certFile, keyFile := writeTempCert(t, "initial")
	rc, err := tlsconfig.New(certFile, keyFile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cert, err := rc.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}
}

func TestNew_InvalidFile_ReturnsError(t *testing.T) {
	_, err := tlsconfig.New("/nonexistent/cert.pem", "/nonexistent/key.pem")
	if err == nil {
		t.Fatal("expected error for nonexistent files")
	}
}

func TestGetClientCertificate_ReturnsSameCert(t *testing.T) {
	certFile, keyFile := writeTempCert(t, "client")
	rc, err := tlsconfig.New(certFile, keyFile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cert, err := rc.GetClientCertificate(nil)
	if err != nil {
		t.Fatalf("GetClientCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}
}

func TestReload_PicksUpNewCert(t *testing.T) {
	certFile, keyFile := writeTempCert(t, "v1")
	rc, err := tlsconfig.New(certFile, keyFile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	first, err := rc.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate (first): %v", err)
	}

	time.Sleep(10 * time.Millisecond)
	writeCertToFiles(t, certFile, keyFile, "v2")

	if err := rc.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	second, err := rc.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate (second): %v", err)
	}

	if first == second {
		t.Fatal("expected cert pointer to change after reload")
	}
}

func TestWatchAndReload_AutomaticallyPicksUpChange(t *testing.T) {
	certFile, keyFile := writeTempCert(t, "watch-v1")
	rc, err := tlsconfig.New(certFile, keyFile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	stop := rc.Watch(20 * time.Millisecond)
	t.Cleanup(func() { close(stop) })

	first, _ := rc.GetCertificate(nil)

	time.Sleep(10 * time.Millisecond)
	writeCertToFiles(t, certFile, keyFile, "watch-v2")

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		time.Sleep(30 * time.Millisecond)
		second, _ := rc.GetCertificate(nil)
		if first != second {
			return
		}
	}
	t.Fatal("cert was not reloaded within 500ms after file change")
}

func writeTempCert(t *testing.T, cn string) (certFile, keyFile string) {
	t.Helper()
	cf, err := os.CreateTemp(t.TempDir(), "cert*.pem")
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	kf, err := os.CreateTemp(t.TempDir(), "key*.pem")
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	cf.Close()
	kf.Close()
	writeCertToFiles(t, cf.Name(), kf.Name(), cn)
	return cf.Name(), kf.Name()
}

func writeCertToFiles(t *testing.T, certFile, keyFile, cn string) {
	t.Helper()
	cert, key := generateSelfSignedCert(t, cn)
	if err := os.WriteFile(certFile, cert, 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, key, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

func generateSelfSignedCert(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return
}

func TestMTLS_AcceptsValidClientCert(t *testing.T) {
	ca, caKey := generateCA(t)
	serverCert, serverKey := generateSignedCert(t, ca, caKey, "server")
	clientCert, clientKey := generateSignedCert(t, ca, caKey, "client")

	serverCertFile, serverKeyFile := writePairToTemp(t, serverCert, serverKey)
	clientCertFile, clientKeyFile := writePairToTemp(t, clientCert, clientKey)

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca)

	serverRC, err := tlsconfig.New(serverCertFile, serverKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	clientRC, err := tlsconfig.New(clientCertFile, clientKeyFile)
	if err != nil {
		t.Fatal(err)
	}

	serverTLS := &tls.Config{
		GetCertificate: serverRC.GetCertificate,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      caPool,
	}
	clientTLS := &tls.Config{
		GetClientCertificate: clientRC.GetClientCertificate,
		RootCAs:              caPool,
		ServerName:           "server",
	}

	serverConn, clientConn := newConnPair()
	server := tls.Server(serverConn, serverTLS)
	client := tls.Client(clientConn, clientTLS)
	defer server.Close()
	defer client.Close()

	serverErrCh := make(chan error, 1)
	go func() { serverErrCh <- server.Handshake() }()

	if err := client.Handshake(); err != nil {
		t.Fatalf("mTLS handshake failed: %v", err)
	}
	if err := <-serverErrCh; err != nil {
		t.Fatalf("server-side mTLS handshake failed: %v", err)
	}
}

func TestMTLS_RejectsNoClientCert(t *testing.T) {
	ca, caKey := generateCA(t)
	serverCert, serverKey := generateSignedCert(t, ca, caKey, "server")

	serverCertFile, serverKeyFile := writePairToTemp(t, serverCert, serverKey)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca)

	serverRC, err := tlsconfig.New(serverCertFile, serverKeyFile)
	if err != nil {
		t.Fatal(err)
	}

	serverTLS := &tls.Config{
		GetCertificate: serverRC.GetCertificate,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      caPool,
	}
	clientTLS := &tls.Config{
		RootCAs:    caPool,
		ServerName: "server",
	}

	serverConn, clientConn := newConnPair()
	server := tls.Server(serverConn, serverTLS)
	client := tls.Client(clientConn, clientTLS)
	defer server.Close()
	defer client.Close()

	serverErrCh := make(chan error, 1)
	go func() { serverErrCh <- server.Handshake() }()

	clientErr := client.Handshake()
	serverErr := <-serverErrCh

	// In TLS 1.3, the client may complete its side before receiving the server's
	// rejection alert — so we check that at least the server rejected the connection.
	if clientErr == nil && serverErr == nil {
		t.Fatal("expected server to reject connection without client cert")
	}
}

func newConnPair() (net.Conn, net.Conn) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ch := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		ln.Close()
		ch <- c
	}()
	client, _ := net.Dial("tcp", ln.Addr().String())
	server := <-ch
	return server, client
}

func generateCA(t *testing.T) (caPEM, caKeyPEM []byte) {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	caKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return
}

func generateSignedCert(t *testing.T, caPEM, caKeyPEM []byte, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	caBlock, _ := pem.Decode(caPEM)
	ca, _ := x509.ParseCertificate(caBlock.Bytes)
	keyBlock, _ := pem.Decode(caKeyPEM)
	caKey, _ := x509.ParseECPrivateKey(keyBlock.Bytes)

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, ca, &priv.PublicKey, caKey)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return
}

func writePairToTemp(t *testing.T, certPEM, keyPEM []byte) (certFile, keyFile string) {
	t.Helper()
	dir := t.TempDir()
	certFile = dir + "/cert.pem"
	keyFile = dir + "/key.pem"
	os.WriteFile(certFile, certPEM, 0600)
	os.WriteFile(keyFile, keyPEM, 0600)
	return
}
