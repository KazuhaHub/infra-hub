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
	"strings"
	"testing"
	"time"
)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func keyPin(t *testing.T, k *ecdsa.PrivateKey) string {
	t.Helper()
	p, err := PinOfKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// certFor makes a self-signed certificate for key with the given template changes.
func certFor(t *testing.T, key *ecdsa.PrivateKey, tweak func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"hub.example.org"}}
	if tweak != nil {
		tweak(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func ders(cs ...*x509.Certificate) [][]byte {
	var out [][]byte
	for _, c := range cs {
		out = append(out, c.Raw)
	}
	return out
}

func TestTheKeyIsTheTrust(t *testing.T) {
	key := newKey(t)
	v := Verifier{Pins: []string{keyPin(t, key)}, Host: "192.0.2.1"}
	accepted := map[string]*x509.Certificate{
		"self-signed": certFor(t, key, nil),
		"expired": certFor(t, key, func(c *x509.Certificate) {
			c.NotBefore, c.NotAfter = time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)
		}),
		"not yet valid": certFor(t, key, func(c *x509.Certificate) {
			c.NotBefore, c.NotAfter = time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour)
		}),
		"wrong name": certFor(t, key, func(c *x509.Certificate) { c.DNSNames = []string{"other.example.net"} }),
		"no name":    certFor(t, key, func(c *x509.Certificate) { c.DNSNames = nil }),
		"CA flag":    certFor(t, key, func(c *x509.Certificate) { c.IsCA, c.BasicConstraintsValid = true, true }),
	}
	for name, c := range accepted {
		if err := v.VerifyChain(ders(c)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Extra certificates after the leaf are ignored.
	if err := v.VerifyChain(ders(accepted["self-signed"], certFor(t, newKey(t), nil))); err != nil {
		t.Errorf("with a trailing certificate: %v", err)
	}
	// Only the leaf counts: a pinned key in a later certificate does not help.
	if err := v.VerifyChain(ders(certFor(t, newKey(t), nil), accepted["self-signed"])); err == nil {
		t.Error("a pinned key behind another leaf was accepted")
	}
	// A different key is refused, even with the same subject and names.
	if err := v.VerifyChain(ders(certFor(t, newKey(t), nil))); err == nil {
		t.Error("a different key was accepted")
	}
}

func TestMultiplePinsAllowRotation(t *testing.T) {
	oldKey, newK := newKey(t), newKey(t)
	both := Verifier{Pins: []string{keyPin(t, oldKey), keyPin(t, newK)}}
	for name, k := range map[string]*ecdsa.PrivateKey{"old": oldKey, "new": newK} {
		if err := both.VerifyChain(ders(certFor(t, k, nil))); err != nil {
			t.Errorf("%s key: %v", name, err)
		}
	}
	onlyOld := Verifier{Pins: []string{keyPin(t, oldKey)}}
	if err := onlyOld.VerifyChain(ders(certFor(t, newK, nil))); err == nil {
		t.Error("the new key was accepted by an agent that only knows the old pin")
	}
	if err := both.VerifyChain(ders(certFor(t, newKey(t), nil))); err == nil {
		t.Error("a third key was accepted")
	}
}

func TestRefusals(t *testing.T) {
	key := newKey(t)
	good := Verifier{Pins: []string{keyPin(t, key)}}
	leaf := certFor(t, key, nil)
	cases := map[string]struct {
		v   Verifier
		raw [][]byte
	}{
		"no certificates": {good, nil},
		"garbage":         {good, [][]byte{[]byte("not a certificate")}},
		"empty":           {good, [][]byte{{}}},
		"too many":        {good, [][]byte{leaf.Raw, leaf.Raw, leaf.Raw, leaf.Raw, leaf.Raw, leaf.Raw, leaf.Raw, leaf.Raw, leaf.Raw}},
		"no pins":         {Verifier{}, ders(leaf)},
		"bad pin":         {Verifier{Pins: []string{"sha256//nope"}}, ders(leaf)},
		"no prefix":       {Verifier{Pins: []string{strings.TrimPrefix(keyPin(t, key), "sha256//")}}, ders(leaf)},
		"one bad of two":  {Verifier{Pins: []string{keyPin(t, key), "bogus"}}, ders(leaf)},
	}
	for name, c := range cases {
		if err := c.v.VerifyChain(c.raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPinFormat(t *testing.T) {
	key := newKey(t)
	pin := keyPin(t, key)
	if !strings.HasPrefix(pin, "sha256//") || len(pin) != len("sha256//")+44 {
		t.Fatalf("pin %q", pin)
	}
	if _, err := ParsePin(pin); err != nil {
		t.Error(err)
	}
	if got := Pin(certFor(t, key, nil)); got != pin {
		t.Errorf("certificate pin %q, key pin %q", got, pin)
	}
}

// The TLS configuration works in a real handshake over TLS 1.3: a server with the pinned key is trusted whatever its
// certificate says about names and dates; another key is not.
func TestTLSConfigHandshake(t *testing.T) {
	key := newKey(t)
	leaf := certFor(t, key, func(c *x509.Certificate) {
		c.DNSNames, c.IPAddresses = []string{"wrong.example.net"}, nil
		c.NotBefore, c.NotAfter = time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)
	})
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	ts.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw}, PrivateKey: key}}}
	ts.StartTLS()
	defer ts.Close()
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "https://"))
	get := func(v Verifier) error {
		cl := &http.Client{Transport: &http.Transport{TLSClientConfig: v.TLSConfig()}, Timeout: 5 * time.Second}
		resp, err := cl.Get(ts.URL)
		if err == nil {
			if resp.TLS == nil || resp.TLS.Version != tls.VersionTLS13 {
				t.Errorf("negotiated TLS version %v, want 1.3", resp.TLS)
			}
			resp.Body.Close()
		}
		return err
	}
	if err := get(Verifier{Pins: []string{keyPin(t, key)}, Host: host}); err != nil {
		t.Errorf("handshake with the right pin: %v", err)
	}
	// A port in Host is stripped for the server name.
	if err := get(Verifier{Pins: []string{keyPin(t, key)}, Host: net.JoinHostPort(host, "443")}); err != nil {
		t.Errorf("host with a port: %v", err)
	}
	if err := get(Verifier{Pins: []string{keyPin(t, newKey(t))}, Host: host}); err == nil {
		t.Error("handshake with the wrong pin succeeded")
	}
}

// A resumed session skips the certificate exchange; the pins must still be checked, so an agent whose pins changed
// (the old key retired) does not resume a session with a hub it no longer trusts.
func TestResumedSessionIsCheckedAgainstTheCurrentPins(t *testing.T) {
	key := newKey(t)
	leaf := certFor(t, key, nil)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if tc := c.(*tls.Conn); tc.Handshake() == nil {
					tc.Write([]byte("x")) // the ticket travels after the handshake; the client reads it
				}
			}()
		}
	}()
	cache := tls.NewLRUClientSessionCache(4)
	var lastVerifyResumed bool
	dial := func(pin string) (resumed bool, err error) {
		cfg := Verifier{Pins: []string{pin}}.TLSConfig()
		cfg.ClientSessionCache = cache
		inner := cfg.VerifyConnection
		var sawResume bool
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			sawResume = cs.DidResume
			return inner(cs)
		}
		defer func() { lastVerifyResumed = sawResume }()
		conn, err := tls.Dial("tcp", ln.Addr().String(), cfg)
		if err != nil {
			return false, err
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		conn.Read(make([]byte, 1))
		return conn.ConnectionState().DidResume, nil
	}
	good := keyPin(t, key)
	if resumed, err := dial(good); err != nil || resumed {
		t.Fatalf("first handshake: resumed=%v err=%v", resumed, err)
	}
	if resumed, err := dial(good); err != nil || !resumed {
		t.Fatalf("second handshake with the same pin: resumed=%v err=%v (the test needs a resumable session)", resumed, err)
	}
	if _, err := dial(keyPin(t, newKey(t))); err == nil {
		t.Error("a session was resumed with a hub whose key is no longer pinned")
	}
	if !lastVerifyResumed {
		t.Error("the refused handshake was not a resumption: the test does not show that resumed sessions are checked")
	}
}
