package hubkey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/hubtrust"
)

func TestWriteNewRefusesToOverwriteAndReadRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.key")
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteNew(path, k); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
	got, err := Read(path)
	if err != nil || !got.Equal(k) {
		t.Fatalf("read: %v", err)
	}
	if err := WriteNew(path, k); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Errorf("second write: %v", err)
	}
	if again, _ := Read(path); !again.Equal(k) {
		t.Error("the key was replaced")
	}
}

func TestReadRefusals(t *testing.T) {
	dir := t.TempDir()
	k, _ := Generate()
	loose := filepath.Join(dir, "loose")
	data, _ := Marshal(k)
	os.WriteFile(loose, data, 0o644)
	if _, err := Read(loose); err == nil || !strings.Contains(err.Error(), "0600 or 0400") {
		t.Errorf("loose mode: %v", err)
	}
	for name, content := range map[string]string{"garbage": "hello", "empty": "", "wrong type": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"} {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(content), 0o600)
		if _, err := Read(p); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := Read(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("directory: %v", err)
	}
	if _, err := Read(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file accepted")
	}
}

func TestCertificate(t *testing.T) {
	k, _ := Generate()
	now := time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)
	tc, err := Certificate(k, []string{"192.0.2.10", "2001:db8::1", "hub.example.org"}, now)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(tc.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if !c.NotBefore.Equal(now.Add(-time.Hour)) {
		t.Errorf("notBefore %v", c.NotBefore)
	}
	if !c.NotAfter.Equal(time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)) {
		t.Errorf("notAfter %v", c.NotAfter)
	}
	if len(c.IPAddresses) != 2 || len(c.DNSNames) != 1 || c.DNSNames[0] != "hub.example.org" {
		t.Errorf("SAN: %v %v", c.IPAddresses, c.DNSNames)
	}
	if err := c.CheckSignatureFrom(c); err == nil && c.IsCA {
		t.Error("the certificate is a CA")
	}
	pub := c.PublicKey.(*ecdsa.PublicKey)
	if c.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("signature algorithm %v", c.SignatureAlgorithm)
	}
	if !pub.Equal(k.Public()) {
		t.Error("certificate is not for the key")
	}
	pin, _ := Pin(k)
	if hubtrust.Pin(c) != pin {
		t.Error("pin mismatch")
	}
	// Two builds of the same key give the same pin (the fingerprint is the key's).
	tc2, _ := Certificate(k, nil, now)
	c2, _ := x509.ParseCertificate(tc2.Certificate[0])
	if hubtrust.Pin(c2) != pin {
		t.Error("second certificate has another pin")
	}
}

func TestGenerateIsP256(t *testing.T) {
	k, err := Generate()
	if err != nil || k.Curve != elliptic.P256() {
		t.Fatalf("%v %v", k, err)
	}
	data, _ := Marshal(k)
	if !strings.HasPrefix(string(data), "-----BEGIN PRIVATE KEY-----") {
		t.Errorf("PEM type: %.40s", data)
	}
}

// Only ECDSA P-256 is accepted: the system curl of macOS (LibreSSL) cannot do a TLS handshake with other key types.
func TestOtherKeyTypesAreRefused(t *testing.T) {
	dir := t.TempDir()
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	for name, key := range map[string]any{"Ed25519": ed, "ECDSA P-384": p384, "RSA": rk} {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "_"))
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = Read(path)
		if err == nil || !strings.Contains(err.Error(), "P-256") || !strings.Contains(err.Error(), "key init") || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
