package httpsapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/hubca"
	"github.com/KazuhaHub/infra-hub/internal/hubtrust"
)

func TestKeyIsCreatedOnceWithMode0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k")
	k1, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if k1.Curve != elliptic.P256() {
		t.Error("not P-256")
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
	k2, err := LoadOrCreateKey(path)
	if err != nil || !k1.Equal(k2) {
		t.Errorf("second call: %v", err)
	}
}

func TestServingCertIsRefusedUnlessItChainsToTheCA(t *testing.T) {
	p := newPKI(t)
	if _, err := LoadServingCert(p.key, p.certPath, p.caPath, p.addresses, t0.Add(time.Hour)); err != nil {
		t.Fatalf("good certificate refused: %v", err)
	}

	// Signed by another CA.
	otherDir := t.TempDir()
	if _, err := hubca.Init(otherDir, t0, hubca.Constraints{}); err != nil {
		t.Fatal(err)
	}
	otherCert, _ := hubca.ReadCertificate(filepath.Join(otherDir, hubca.CertFile))
	otherKey, _ := hubca.ReadPrivateKey(filepath.Join(otherDir, hubca.KeyFile))
	foreign := filepath.Join(t.TempDir(), "foreign.crt")
	p.sign(t, foreign, otherKey, otherCert, p.key, p.addresses)
	if _, err := LoadServingCert(p.key, foreign, p.caPath, p.addresses, t0.Add(time.Hour)); err == nil || !strings.Contains(err.Error(), "chain") {
		t.Errorf("certificate of another CA accepted: %v", err)
	}

	// A self-signed certificate.
	selfSigned := filepath.Join(t.TempDir(), "self.crt")
	selfTmpl := &x509.Certificate{SerialNumber: bigOne(), NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(24 * time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames: []string{"hub.example.org"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, selfTmpl, selfTmpl, &p.key.PublicKey, p.key)
	os.WriteFile(selfSigned, pemCert(der), 0o644)
	if _, err := LoadServingCert(p.key, selfSigned, p.caPath, p.addresses, t0.Add(time.Hour)); err == nil {
		t.Error("self-signed certificate accepted")
	}

	// A certificate for another key.
	stranger, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := LoadServingCert(stranger, p.certPath, p.caPath, p.addresses, t0.Add(time.Hour)); err == nil || !strings.Contains(err.Error(), "match") {
		t.Errorf("certificate with a different key accepted: %v", err)
	}
	// Expired, and not yet valid.
	if _, err := LoadServingCert(p.key, p.certPath, p.caPath, p.addresses, t0.Add(900*24*time.Hour)); err == nil {
		t.Error("expired certificate accepted")
	}
	if _, err := LoadServingCert(p.key, p.certPath, p.caPath, p.addresses, t0.Add(-time.Hour)); err == nil {
		t.Error("not-yet-valid certificate accepted")
	}
	// Missing a configured name.
	if _, err := LoadServingCert(p.key, p.certPath, p.caPath, append([]string{"192.0.2.99"}, p.addresses...), t0.Add(time.Hour)); err == nil || !strings.Contains(err.Error(), "cover") {
		t.Errorf("certificate missing a configured address accepted: %v", err)
	}
	// Missing files, and garbage.
	if _, err := LoadServingCert(p.key, filepath.Join(t.TempDir(), "none"), p.caPath, p.addresses, t0); err == nil {
		t.Error("missing certificate accepted")
	}
	garbage := filepath.Join(t.TempDir(), "g")
	os.WriteFile(garbage, []byte("not pem"), 0o644)
	if _, err := LoadServingCert(p.key, garbage, p.caPath, p.addresses, t0); err == nil {
		t.Error("garbage accepted")
	}
}

// runHTTPS starts a Runner and returns the address it listens on (or "" if it did not start within wait).
func runHTTPS(t *testing.T, p *pki, certPath string, h *testHub, wait time.Duration) (addr string, csrPath string) {
	t.Helper()
	csrPath = filepath.Join(p.dir, "hub.csr")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.Cleanup(func() { cancel(); <-done })
	ch := make(chan string, 1)
	r := &Runner{Identity: Identity{KeyPath: p.keyPath, CSRPath: csrPath, CertPath: certPath, CAPath: p.caPath, Addresses: p.addresses},
		Listen: "127.0.0.1:0", Server: h.s, Now: func() time.Time { return t0.Add(time.Hour) }, RetryEvery: 20 * time.Millisecond,
		OnListen: func(a net.Addr) { ch <- a.String() }}
	go func() { defer close(done); r.Run(ctx) }()
	select {
	case addr = <-ch:
	case <-time.After(wait):
	}
	return addr, csrPath
}

func pinnedClient(p *pki, maxVersion uint16) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(p.caCert)
	conf := &tls.Config{RootCAs: pool, ServerName: "hub.example.org"}
	if maxVersion != 0 {
		conf.MaxVersion = maxVersion
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: conf}, Timeout: 5 * time.Second}
}

func TestHTTPSServesToAClientThatPinsTheCA(t *testing.T) {
	p := newPKI(t)
	h := newHub(t)
	addr, _ := runHTTPS(t, p, p.certPath, h, 5*time.Second)
	if addr == "" {
		t.Fatal("the hub did not serve HTTPS")
	}
	get := func(c *http.Client, path string) (*http.Response, error) { return c.Get("https://" + addr + path) }

	resp, err := get(pinnedClient(p, 0), "/v1/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]string
	json.NewDecoder(resp.Body).Decode(&doc)
	if resp.StatusCode != 200 || doc["status"] != "ok" || doc["apiVersion"] != "v1" || resp.TLS.Version != tls.VersionTLS13 {
		t.Errorf("healthz: %d %v tls=%x", resp.StatusCode, doc, resp.TLS.Version)
	}

	// The hub presents its certificate and the CA certificate, so a client that holds only the CA pin trusts it.
	if len(resp.TLS.PeerCertificates) != 2 || !resp.TLS.PeerCertificates[1].Equal(p.caCert) {
		t.Errorf("presented chain has %d certificates, want hub + CA", len(resp.TLS.PeerCertificates))
	}
	byPin := hubtrust.Verifier{Pins: []string{hubca.Pin(p.caCert)}, Host: "127.0.0.1", Now: func() time.Time { return t0.Add(time.Hour) }}
	pc := &http.Client{Transport: &http.Transport{TLSClientConfig: byPin.TLSConfig()}, Timeout: 5 * time.Second}
	if r, err := get(pc, "/v1/healthz"); err != nil {
		t.Errorf("client with only the CA pin: %v", err)
	} else {
		r.Body.Close()
	}
	byPin.Pins = []string{"sha256//" + strings.Repeat("A", 43) + "="}
	pc = &http.Client{Transport: &http.Transport{TLSClientConfig: byPin.TLSConfig()}, Timeout: 5 * time.Second}
	if _, err := get(pc, "/v1/healthz"); err == nil {
		t.Error("client with the wrong CA pin trusted the hub")
	}

	// TLS 1.2 is refused.
	if _, err := get(pinnedClient(p, tls.VersionTLS12), "/v1/healthz"); err == nil {
		t.Error("a TLS 1.2 client was served")
	}
	// A client that trusts a different CA (or only the system roots) refuses the hub.
	otherDir := t.TempDir()
	hubca.Init(otherDir, t0, hubca.Constraints{})
	otherCA, _ := hubca.ReadCertificate(filepath.Join(otherDir, hubca.CertFile))
	pool := x509.NewCertPool()
	pool.AddCert(otherCA)
	wrong := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "hub.example.org"}}, Timeout: 5 * time.Second}
	if _, err := get(wrong, "/v1/healthz"); err == nil {
		t.Error("a client with another CA accepted the hub")
	}
	if _, err := get(&http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{ServerName: "hub.example.org"}}}, "/v1/healthz"); err == nil {
		t.Error("a client with the system roots accepted the hub")
	}

	// A full challenge and report round trip over TLS.
	c := pinnedClient(p, 0)
	cr, err := c.Post("https://"+addr+"/v1/challenge", "application/json", strings.NewReader(`{"host":"h1"}`))
	if err != nil {
		t.Fatal(err)
	}
	var ch map[string]string
	json.NewDecoder(cr.Body).Decode(&ch)
	cr.Body.Close()
	nonce := decryptChallenge(t, h.ids["h1"], ch["challenge"])
	rr, err := c.Post("https://"+addr+"/v1/report", "application/json", strings.NewReader(reportBodyFor("h1", nonce, goodReport)))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(rr.Body)
	rr.Body.Close()
	if rr.StatusCode != 200 {
		t.Errorf("report over TLS: %d %s", rr.StatusCode, body)
	}
}

func TestHubDoesNotServeHTTPSWithAnUnsignedCertificate(t *testing.T) {
	p := newPKI(t)
	h := newHub(t)
	// A certificate from another CA is configured: no listener, and a request is written.
	otherDir := t.TempDir()
	hubca.Init(otherDir, t0, hubca.Constraints{})
	otherCert, _ := hubca.ReadCertificate(filepath.Join(otherDir, hubca.CertFile))
	otherKey, _ := hubca.ReadPrivateKey(filepath.Join(otherDir, hubca.KeyFile))
	foreign := filepath.Join(t.TempDir(), "foreign.crt")
	p.sign(t, foreign, otherKey, otherCert, p.key, p.addresses)
	if addr, _ := runHTTPS(t, p, foreign, h, 400*time.Millisecond); addr != "" {
		t.Fatalf("the hub served HTTPS with a certificate of another CA on %s", addr)
	}
}

func TestMissingCertificateWritesACSRAndServesLaterWhenPlaced(t *testing.T) {
	p := newPKI(t)
	h := newHub(t)
	later := filepath.Join(t.TempDir(), "placed.crt") // does not exist yet
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	csrPath := filepath.Join(p.dir, "hub.csr")
	ch := make(chan string, 1)
	r := &Runner{Identity: Identity{KeyPath: p.keyPath, CSRPath: csrPath, CertPath: later, CAPath: p.caPath, Addresses: p.addresses},
		Listen: "127.0.0.1:0", Server: h.s, Now: func() time.Time { return t0.Add(time.Hour) }, RetryEvery: 20 * time.Millisecond,
		OnListen: func(a net.Addr) { ch <- a.String() }}
	go r.Run(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(csrPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no certificate request was written")
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case a := <-ch:
		t.Fatalf("served on %s without a certificate", a)
	case <-time.After(150 * time.Millisecond):
	}
	// The request carries the configured names and the hub's key, and the CA can sign it.
	csrPEM, _ := os.ReadFile(csrPath)
	cert, _, err := hubca.Sign(hubca.SignOptions{CAKey: p.caKey, CACert: p.caCert, CSRPEM: csrPEM, Now: t0})
	if err != nil {
		t.Fatalf("the written request cannot be signed: %v", err)
	}
	parsed, _ := hubca.ParseCertificatePEM(cert)
	if !parsed.PublicKey.(*ecdsa.PublicKey).Equal(&p.key.PublicKey) || parsed.VerifyHostname("hub.example.org") != nil || parsed.VerifyHostname("127.0.0.1") != nil {
		t.Error("request does not carry the hub's key and names")
	}
	// Placing the certificate starts HTTPS without a restart.
	if err := os.WriteFile(later, cert, 0o644); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("HTTPS did not start after the certificate was placed")
	}
}

func TestEnsureCSRCreatesTheKey(t *testing.T) {
	dir := t.TempDir()
	id := Identity{KeyPath: filepath.Join(dir, "k"), CSRPath: filepath.Join(dir, "c"), Addresses: []string{"192.0.2.5", "hub.example.org"}}
	csr, err := id.EnsureCSR()
	if err != nil || !strings.Contains(string(csr), "BEGIN CERTIFICATE REQUEST") {
		t.Fatalf("%v %s", err, csr)
	}
	if st, err := os.Stat(id.KeyPath); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("key: %v", err)
	}
}

func TestKeyWithLooseModeIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k")
	if _, err := LoadOrCreateKey(path); err != nil {
		t.Fatal(err)
	}
	os.Chmod(path, 0o644)
	if _, err := LoadOrCreateKey(path); err == nil {
		t.Error("a world-readable key was accepted")
	}
}
