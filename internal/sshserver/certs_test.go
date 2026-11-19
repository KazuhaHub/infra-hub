package sshserver

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/KazuhaHub/infra-hub/internal/certs"
)

// makeBundle builds a leaf for the names (signed by a throwaway intermediate) that expires at notAfter.
func makeBundle(t *testing.T, notAfter time.Time, names ...string) certs.Bundle {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	return certs.Bundle{Fullchain: chain, Privkey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})}
}

func certHub(t *testing.T, life time.Duration) (*testHub, *certs.CertManager) {
	t.Helper()
	m := &certs.CertManager{Store: certs.CertStore{Dir: t.TempDir()}, Owners: map[string]string{"a.example.org": "host-a", "unissued.example.org": "host-a"}}
	if err := m.Store.SaveBundle("a.example.org", makeBundle(t, time.Now().Add(life), "a.example.org")); err != nil {
		t.Fatal(err)
	}
	return startHub(t, func(h *testHub) { h.srv.Certs = m }), m
}

// runCert runs one exec as host and returns stdout, stderr and the error from Run (exit status or refusal).
func runCert(t *testing.T, h *testHub, host, cmd string) (string, string, error) {
	t.Helper()
	c, err := h.dial(h.clients[host], "infra")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	s.Stdout, s.Stderr = &out, &errb
	err = s.Run(cmd)
	return out.String(), errb.String(), err
}

func TestCertOwnerGetsStrictJSON(t *testing.T) {
	h, _ := certHub(t, 60*24*time.Hour)
	out, _, err := runCert(t, h, "host-a", "cert a.example.org")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(out, "\n") || strings.Count(out, "\n") != 1 {
		t.Fatalf("not exactly one line: %q", out)
	}
	dec := json.NewDecoder(strings.NewReader(out))
	dec.DisallowUnknownFields()
	var p certs.CertPayload
	if err := dec.Decode(&p); err != nil {
		t.Fatal(err)
	}
	if p.Name != "a.example.org" || !strings.HasPrefix(p.Fullchain, "-----BEGIN CERTIFICATE-----") || !strings.Contains(p.Privkey, "PRIVATE KEY") {
		t.Fatalf("%+v", p)
	}
	na, err := time.Parse(time.RFC3339, p.NotAfter)
	if err != nil || time.Until(na) < 59*24*time.Hour {
		t.Fatalf("not_after %q", p.NotAfter)
	}
	var raw map[string]any
	json.Unmarshal([]byte(out), &raw)
	if len(raw) != 4 {
		t.Fatalf("keys: %v", raw)
	}
}

func TestCertOtherHostAndUnknownNameAreRefused(t *testing.T) {
	h, _ := certHub(t, 60*24*time.Hour)
	var first string
	for i, c := range []struct{ host, cmd string }{
		{"host-b", "cert a.example.org"},     // not the owner
		{"host-a", "cert nope.example.org"},  // unknown name
		{"host-a", "cert a.example.org."},    // trailing dot
		{"host-a", "cert A.example.org"},     // upper case
		{"host-a", "cert A.EXAMPLE.ORG"},     // upper case
		{"host-a", "cert ../a.example.org"},  // not a name at all
		{"host-a", "cert a.example.org x"},   // extra argument
		{"host-a", "cert a.example.org; id"}, // injection attempt
		{"host-a", "cert"},
	} {
		out, _, err := runCert(t, h, c.host, c.cmd)
		var ee *ssh.ExitError
		// a refused exec request: the command never starts, so there is no exit status and nothing on stdout
		if err == nil || errors.As(err, &ee) || out != "" {
			t.Errorf("%s %q: err=%v (%T) out=%q", c.host, c.cmd, err, err, out)
			continue
		}
		msg := strings.Replace(err.Error(), c.cmd, "<cmd>", 1) // the client library puts the command in the message
		if i == 0 {
			first = msg
		} else if msg != first {
			t.Errorf("%s %q: refusal %q differs from the non-owner refusal %q", c.host, c.cmd, msg, first)
		}
	}
}

func TestCertRefusedUnder7DaysAndWhenMissing(t *testing.T) {
	h, _ := certHub(t, 6*24*time.Hour)
	out, errOut, err := runCert(t, h, "host-a", "cert a.example.org")
	var ee *ssh.ExitError
	if !errors.As(err, &ee) || ee.ExitStatus() != 1 || out != "" || !strings.Contains(errOut, "less than 7 days") {
		t.Fatalf("err=%v out=%q stderr=%q", err, out, errOut)
	}
	out, _, err = runCert(t, h, "host-a", "cert unissued.example.org")
	if !errors.As(err, &ee) || out != "" {
		t.Fatalf("err=%v out=%q", err, out)
	}
}

func TestCertIgnoresStaleMirrorAndGitStillRefuses(t *testing.T) {
	h, _ := certHub(t, 60*24*time.Hour)
	h.srv.Fresh = func() error { return errors.New("mirror too old") }
	if _, _, err := runCert(t, h, "host-a", "cert a.example.org"); err != nil {
		t.Fatalf("stale mirror blocked a certificate: %v", err)
	}
	_, errOut, err := runCert(t, h, "host-a", "git-upload-pack '/infra.git'")
	if err == nil || !strings.Contains(errOut, "not serving") {
		t.Fatalf("git was served from a stale mirror: err=%v %q", err, errOut)
	}
}

func TestCertWithoutProviderIsRefused(t *testing.T) {
	h := startHub(t)
	if _, _, err := runCert(t, h, "host-a", "cert a.example.org"); err == nil {
		t.Fatal("cert served with no certificate source")
	}
}

func TestCertUsesTheSlotLimits(t *testing.T) {
	h, _ := certHub(t, 60*24*time.Hour)
	h.srv.PerHostMax = 0
	if _, _, err := runCert(t, h, "host-a", "cert a.example.org"); err == nil {
		t.Fatal("the per-host limit does not apply to cert")
	}
	h.srv.PerHostMax = 2
	if _, _, err := runCert(t, h, "host-a", "cert a.example.org"); err != nil {
		t.Fatal(err)
	}
	// the slot is released after the command
	for i := 0; i < 5; i++ {
		if _, _, err := runCert(t, h, "host-a", "cert a.example.org"); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
}
