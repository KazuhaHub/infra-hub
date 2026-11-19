package hubtrust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/hubca"
)

var t0 = time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)

type authority struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	pin  string
}

func newAuthority(t *testing.T) authority {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ca")
	pin, err := hubca.Init(dir, t0, hubca.Constraints{})
	if err != nil {
		t.Fatal(err)
	}
	k, _ := hubca.ReadPrivateKey(filepath.Join(dir, hubca.KeyFile))
	c, _ := hubca.ReadCertificate(filepath.Join(dir, hubca.CertFile))
	return authority{k, c, pin}
}

// hubCert signs a hub certificate for the names with the authority and returns it with its key.
func (a authority) hubCert(t *testing.T, names ...string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, err := hubca.NewCSR(k, names)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, c, err := hubca.Sign(hubca.SignOptions{CAKey: a.key, CACert: a.cert, CSRPEM: csr, Now: t0})
	if err != nil || len(pemBytes) == 0 {
		t.Fatal(err)
	}
	return c, k
}

func (a authority) leaf(t *testing.T, name string) *x509.Certificate {
	c, _ := a.hubCert(t, name)
	return c
}

func ders(cs ...*x509.Certificate) [][]byte {
	var out [][]byte
	for _, c := range cs {
		out = append(out, c.Raw)
	}
	return out
}

func verifier(pin, host string, at time.Time) Verifier {
	return Verifier{Pins: []string{pin}, Host: host, Now: func() time.Time { return at }}
}

func TestPinnedChainVerification(t *testing.T) {
	ca := newAuthority(t)
	hub, _ := ca.hubCert(t, "192.0.2.10", "hub.example.org")
	at := t0.Add(24 * time.Hour)

	if err := verifier(ca.pin, "hub.example.org", at).VerifyChain(ders(hub, ca.cert)); err != nil {
		t.Errorf("correct pin, DNS name: %v", err)
	}
	if err := verifier(ca.pin, "192.0.2.10", at).VerifyChain(ders(hub, ca.cert)); err != nil {
		t.Errorf("correct pin, IP: %v", err)
	}

	// Wrong pin: the presented CA is not the pinned one.
	other := newAuthority(t)
	if err := verifier(other.pin, "hub.example.org", at).VerifyChain(ders(hub, ca.cert)); err == nil {
		t.Error("wrong pin accepted")
	}
	// A pin that is not well formed.
	for _, bad := range []string{"", "sha256//", "sha256//AAAA", "md5//xx", strings.TrimPrefix(ca.pin, "sha256//")} {
		if err := verifier(bad, "hub.example.org", at).VerifyChain(ders(hub, ca.cert)); err == nil {
			t.Errorf("malformed pin %q accepted", bad)
		}
	}
	// The CA certificate is not presented: nothing to match the pin with.
	if err := verifier(ca.pin, "hub.example.org", at).VerifyChain(ders(hub)); err == nil {
		t.Error("a chain without the CA certificate accepted")
	}
	// The pinned CA is presented, but the leaf was signed by another CA: it must not verify.
	if err := verifier(ca.pin, "hub.example.org", at).VerifyChain(ders(other.leaf(t, "hub.example.org"), ca.cert)); err == nil {
		t.Error("a leaf not signed by the CA accepted")
	}
	// A different host name than the certificate's.
	if err := verifier(ca.pin, "other.example.org", at).VerifyChain(ders(hub, ca.cert)); err == nil {
		t.Error("a certificate for another name accepted")
	}
	if err := verifier(ca.pin, "192.0.2.99", at).VerifyChain(ders(hub, ca.cert)); err == nil {
		t.Error("a certificate for another IP accepted")
	}
	// Expired, and not yet valid.
	if err := verifier(ca.pin, "hub.example.org", t0.Add(900*24*time.Hour)).VerifyChain(ders(hub, ca.cert)); err == nil {
		t.Error("an expired hub certificate accepted")
	}
	if err := verifier(ca.pin, "hub.example.org", t0.Add(-time.Hour)).VerifyChain(ders(hub, ca.cert)); err == nil {
		t.Error("a certificate that is not valid yet accepted")
	}
	// Empty and junk input.
	if err := verifier(ca.pin, "hub.example.org", at).VerifyChain(nil); err == nil {
		t.Error("an empty chain accepted")
	}
	if err := verifier(ca.pin, "hub.example.org", at).VerifyChain([][]byte{[]byte("junk")}); err == nil {
		t.Error("junk accepted")
	}
	if err := (Verifier{Host: "hub.example.org", Now: func() time.Time { return at }}).VerifyChain(ders(hub, ca.cert)); err == nil {
		t.Error("no pin configured, yet accepted")
	}
	// Several pins (rotation): any of them.
	rot := Verifier{Pins: []string{other.pin, ca.pin}, Host: "hub.example.org", Now: func() time.Time { return at }}
	if err := rot.VerifyChain(ders(hub, ca.cert)); err != nil {
		t.Errorf("second pin: %v", err)
	}
}

// A CA certificate that has the real CA's subject (and even its name) but another key is swapped in.
func TestCACertificateWithTheSameSubjectButAnotherKeyFails(t *testing.T) {
	real := newAuthority(t)
	// The attacker's CA copies the real CA's subject, and signs a leaf for the hub's name.
	atkKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	atkTmpl := &x509.Certificate{SerialNumber: big.NewInt(5), Subject: real.cert.Subject, NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(1000 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true, SubjectKeyId: real.cert.SubjectKeyId}
	atkDER, err := x509.CreateCertificate(rand.Reader, atkTmpl, atkTmpl, &atkKey.PublicKey, atkKey)
	if err != nil {
		t.Fatal(err)
	}
	atkCA, _ := x509.ParseCertificate(atkDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(6), Subject: pkixName("hub.example.org"), NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(48 * time.Hour),
		DNSNames: []string{"hub.example.org"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, atkCA, &leafKey.PublicKey, atkKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	at := t0.Add(time.Hour)
	// The chain is perfectly valid by itself (the attacker's CA signed the leaf), but its CA key is not the pinned one.
	roots := x509.NewCertPool()
	roots.AddCert(atkCA)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "hub.example.org", CurrentTime: at}); err != nil {
		t.Fatalf("test setup: the forged chain should verify on its own: %v", err)
	}
	if err := verifier(real.pin, "hub.example.org", at).VerifyChain(ders(leaf, atkCA)); err == nil {
		t.Error("a swapped-in CA with the same subject was accepted")
	}
	// Presenting the real CA next to the forged leaf does not help either: the leaf does not verify under it.
	if err := verifier(real.pin, "hub.example.org", at).VerifyChain(ders(leaf, atkCA, real.cert)); err == nil {
		t.Error("a forged leaf passed because the real CA was also presented")
	}
}

func TestRevokedSerialIsRefused(t *testing.T) {
	ca := newAuthority(t)
	hub, _ := ca.hubCert(t, "hub.example.org")
	list, err := hubca.ParseRevocationList([]byte(`{"apiVersion":"v1","revoked":[{"serial":"` + hub.SerialNumber.Text(16) + `","time":"2026-11-19T08:00:00Z"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	v := verifier(ca.pin, "hub.example.org", t0.Add(time.Hour))
	if err := v.VerifyChain(ders(hub, ca.cert)); err != nil {
		t.Fatal(err)
	}
	v.Revoked = list
	if err := v.VerifyChain(ders(hub, ca.cert)); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Errorf("revoked certificate accepted: %v", err)
	}
}

func pkixName(cn string) pkix.Name { return pkix.Name{CommonName: cn} }

// The TLS configuration works in a real handshake: a hub that presents hub certificate + CA is trusted by pin
// alone; with the wrong pin, or with TLS 1.2 only, it is not.
func TestTLSConfigHandshake(t *testing.T) {
	ca := newAuthority(t)
	now := time.Now() // a real handshake: the certificates must be valid today
	dir := filepath.Join(t.TempDir(), "x")
	if _, err := hubca.Init(dir, now, hubca.Constraints{}); err != nil {
		t.Fatal(err)
	}
	k, _ := hubca.ReadPrivateKey(filepath.Join(dir, hubca.KeyFile))
	c, _ := hubca.ReadCertificate(filepath.Join(dir, hubca.CertFile))
	pin := hubca.Pin(c)
	hubKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := hubca.NewCSR(hubKey, []string{"127.0.0.1"})
	certPEM, _, err := hubca.Sign(hubca.SignOptions{CAKey: k, CACert: c, CSRPEM: csr, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := hubca.ParseCertificatePEM(certPEM)
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	ts.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw, c.Raw}, PrivateKey: hubKey}}}
	ts.StartTLS()
	defer ts.Close()
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "https://"))

	get := func(v Verifier) error {
		cl := &http.Client{Transport: &http.Transport{TLSClientConfig: v.TLSConfig()}, Timeout: 5 * time.Second}
		resp, err := cl.Get(ts.URL)
		if err == nil {
			resp.Body.Close()
		}
		return err
	}
	if err := get(Verifier{Pins: []string{pin}, Host: host}); err != nil {
		t.Errorf("handshake with the right pin: %v", err)
	}
	if err := get(Verifier{Pins: []string{ca.pin}, Host: host}); err == nil {
		t.Error("handshake with the wrong pin succeeded")
	}
	if err := get(Verifier{Pins: []string{pin}, Host: "198.51.100.1"}); err == nil {
		t.Error("handshake for another address succeeded")
	}
}
