package hubca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)

func newCA(t *testing.T, cons Constraints) (dir string, key *ecdsa.PrivateKey, cert *x509.Certificate, pin string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "ca")
	pin, err := Init(dir, now, cons)
	if err != nil {
		t.Fatal(err)
	}
	key, err = ReadPrivateKey(filepath.Join(dir, KeyFile))
	if err != nil {
		t.Fatal(err)
	}
	cert, err = ReadCertificate(filepath.Join(dir, CertFile))
	if err != nil {
		t.Fatal(err)
	}
	return
}

func csrFor(t *testing.T, names ...string) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, err := NewCSR(k, names)
	if err != nil {
		t.Fatal(err)
	}
	return k, csr
}

func TestInitSignPinRoundTrip(t *testing.T) {
	dir, caKey, caCert, pin := newCA(t, Constraints{})
	if !strings.HasPrefix(pin, "sha256//") || pin != Pin(caCert) {
		t.Fatalf("pin %q", pin)
	}
	if !caCert.IsCA || caCert.NotAfter.Sub(caCert.NotBefore) < 19*365*24*time.Hour || caCert.NotAfter.Sub(caCert.NotBefore) > 21*365*24*time.Hour {
		t.Errorf("CA validity %s .. %s", caCert.NotBefore, caCert.NotAfter)
	}
	if caKey.Curve != elliptic.P256() {
		t.Error("CA key is not P-256")
	}
	if st, _ := os.Stat(filepath.Join(dir, KeyFile)); st.Mode().Perm() != 0o600 {
		t.Errorf("ca.key mode %v", st.Mode().Perm())
	}
	if p, err := PinOfKey(caCert.PublicKey); err != nil || p != pin {
		t.Errorf("PinOfKey %q %v", p, err)
	}
	hubKey, csr := csrFor(t, "192.0.2.10", "hub.example.org")
	certPEM, cert, err := Sign(SignOptions{CAKey: caKey, CACert: caCert, CSRPEM: csr, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseCertificatePEM(certPEM)
	if err != nil || parsed.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatalf("parse: %v", err)
	}
	if !parsed.PublicKey.(*ecdsa.PublicKey).Equal(&hubKey.PublicKey) {
		t.Error("certificate is not for the request's key")
	}
	if len(parsed.DNSNames) != 1 || parsed.DNSNames[0] != "hub.example.org" || len(parsed.IPAddresses) != 1 || parsed.IPAddresses[0].String() != "192.0.2.10" {
		t.Errorf("SANs %v %v", parsed.DNSNames, parsed.IPAddresses)
	}
	if got := parsed.NotAfter.Sub(now); got < 824*24*time.Hour || got > 826*24*time.Hour {
		t.Errorf("default validity %s", got)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := parsed.Verify(x509.VerifyOptions{Roots: roots, DNSName: "hub.example.org", CurrentTime: now.Add(time.Hour)}); err != nil {
		t.Errorf("verify: %v", err)
	}
	if _, err := Init(dir, now, Constraints{}); err == nil {
		t.Error("init overwrote an existing CA")
	}
}

func TestSignRefusals(t *testing.T) {
	_, caKey, caCert, _ := newCA(t, Constraints{})
	good := func(names ...string) []byte { _, c := csrFor(t, names...); return c }
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, o := range map[string]SignOptions{
		"days too long": {CAKey: caKey, CACert: caCert, CSRPEM: good("192.0.2.1"), Days: 826},
		"negative days": {CAKey: caKey, CACert: caCert, CSRPEM: good("192.0.2.1"), Days: -1},
		"wrong CA key":  {CAKey: otherKey, CACert: caCert, CSRPEM: good("192.0.2.1")},
		"not a CSR":     {CAKey: caKey, CACert: caCert, CSRPEM: []byte("nope")},
	} {
		o.Now = now
		if _, _, err := Sign(o); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
	// Names the request cannot carry through NewCSR are built by hand.
	for name, tmpl := range map[string]*x509.CertificateRequest{
		"email":    {EmailAddresses: []string{"a@example.org"}, DNSNames: []string{"h.example.org"}},
		"uri":      {DNSNames: []string{"h.example.org"}},
		"wildcard": {DNSNames: []string{"*.example.org"}},
		"no names": {},
	} {
		if name == "uri" {
			u, _ := parseURL("https://h.example.org/x")
			tmpl.URIs = append(tmpl.URIs, u)
		}
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, k)
		if err != nil {
			t.Fatal(err)
		}
		pemBytes := pemEncodeCSR(der)
		if _, _, err := Sign(SignOptions{CAKey: caKey, CACert: caCert, CSRPEM: pemBytes, Now: now}); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
	if _, err := NewCSR(otherKey, []string{"*.example.org"}); err == nil {
		t.Error("NewCSR accepted a wildcard")
	}
}

func TestNameConstraintsHoldAtSigning(t *testing.T) {
	_, caKey, caCert, _ := newCA(t, Constraints{IPs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, Names: []string{"example.org"}})
	if len(caCert.PermittedIPRanges) != 1 || len(caCert.PermittedDNSDomains) != 1 {
		t.Fatalf("constraints missing: %v %v", caCert.PermittedIPRanges, caCert.PermittedDNSDomains)
	}
	_, ok := csrFor(t, "192.0.2.7", "hub.example.org")
	if _, _, err := Sign(SignOptions{CAKey: caKey, CACert: caCert, CSRPEM: ok, Now: now}); err != nil {
		t.Errorf("permitted names refused: %v", err)
	}
	for _, name := range []string{"198.51.100.1", "evil.example.net"} {
		_, bad := csrFor(t, name)
		if _, _, err := Sign(SignOptions{CAKey: caKey, CACert: caCert, CSRPEM: bad, Now: now}); err == nil {
			t.Errorf("%s: signed outside the constraints", name)
		}
	}
}

func TestRevocationList(t *testing.T) {
	good := `{"apiVersion":"v1","revoked":[{"serial":"ff","time":"2026-11-19T09:00:00Z"},{"serial":"1a2b","time":"2026-11-19T08:00:00Z","reason":"key lost"}]}`
	l, err := ParseRevocationList([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if !l.Contains(big.NewInt(0x1a2b)) || !l.Contains(big.NewInt(0xff)) || l.Contains(big.NewInt(5)) {
		t.Error("Contains")
	}
	for name, doc := range map[string]string{
		"no version": `{"revoked":[]}`,
		"v2":         `{"apiVersion":"v2","revoked":[]}`,
		"unknown":    `{"apiVersion":"v1","revoked":[],"x":1}`,
		"upper case": `{"apiVersion":"v1","revoked":[{"serial":"AB","time":"2026-11-19T08:00:00Z"}]}`,
		"leading 0":  `{"apiVersion":"v1","revoked":[{"serial":"0a","time":"2026-11-19T08:00:00Z"}]}`,
		"not hex":    `{"apiVersion":"v1","revoked":[{"serial":"zz","time":"2026-11-19T08:00:00Z"}]}`,
		"duplicate":  `{"apiVersion":"v1","revoked":[{"serial":"ab","time":"2026-11-19T08:00:00Z"},{"serial":"ab","time":"2026-11-19T08:00:00Z"}]}`,
		"unsorted":   `{"apiVersion":"v1","revoked":[{"serial":"ff","time":"2026-11-19T08:00:00Z"},{"serial":"ab","time":"2026-11-19T08:00:00Z"}]}`,
		"bad time":   `{"apiVersion":"v1","revoked":[{"serial":"ab","time":"yesterday"}]}`,
		"trailing":   good + `{}`,
	} {
		if _, err := ParseRevocationList([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Numeric, not textual, order: "ff" (255) comes before "100" (256).
	if _, err := ParseRevocationList([]byte(`{"apiVersion":"v1","revoked":[{"serial":"ff","time":"2026-11-19T08:00:00Z"},{"serial":"100","time":"2026-11-19T08:00:00Z"}]}`)); err != nil {
		t.Errorf("numeric order refused: %v", err)
	}
	if _, err := ParseRevocationList([]byte(`{"apiVersion":"v1","revoked":[{"serial":"100","time":"2026-11-19T08:00:00Z"},{"serial":"ff","time":"2026-11-19T08:00:00Z"}]}`)); err == nil {
		t.Error("text order accepted")
	}
	var nilList *RevocationList
	if nilList.Contains(big.NewInt(1)) {
		t.Error("nil list contains")
	}
}

func TestOneKindOfConstraintExcludesTheOther(t *testing.T) {
	_, ipKey, ipCA, _ := newCA(t, Constraints{IPs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}})
	_, dnsKey, dnsCA, _ := newCA(t, Constraints{Names: []string{"example.org"}})
	_, ok := csrFor(t, "192.0.2.7")
	if _, _, err := Sign(SignOptions{CAKey: ipKey, CACert: ipCA, CSRPEM: ok, Now: now}); err != nil {
		t.Errorf("permitted IP refused: %v", err)
	}
	_, dns := csrFor(t, "hub.example.org")
	if _, _, err := Sign(SignOptions{CAKey: ipKey, CACert: ipCA, CSRPEM: dns, Now: now}); err == nil {
		t.Error("an IP-only CA signed a DNS name")
	}
	if _, _, err := Sign(SignOptions{CAKey: dnsKey, CACert: dnsCA, CSRPEM: dns, Now: now}); err != nil {
		t.Errorf("permitted DNS name refused: %v", err)
	}
	if _, _, err := Sign(SignOptions{CAKey: dnsKey, CACert: dnsCA, CSRPEM: ok, Now: now}); err == nil {
		t.Error("a DNS-only CA signed an IP")
	}
}

func TestTrailingBracketIsRejected(t *testing.T) {
	if _, err := ParseRevocationList([]byte(`{"apiVersion":"v1","revoked":[]}}`)); err == nil {
		t.Error("stray } accepted")
	}
}
