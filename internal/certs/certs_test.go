package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"
)

// makeBundle builds a leaf for the names (signed by a throwaway intermediate) that expires at notAfter.
func makeBundle(t *testing.T, notAfter time.Time, names ...string) Bundle {
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
	return Bundle{Fullchain: chain, Privkey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})}
}

// fakeIssuer needs no network. life is the validity of what it issues.
type fakeIssuer struct {
	mu    sync.Mutex
	t     *testing.T
	life  time.Duration
	err   error
	calls []string
}

func (f *fakeIssuer) Obtain(ctx context.Context, name string) (Bundle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
	if f.err != nil {
		return Bundle{}, f.err
	}
	return makeBundle(f.t, time.Now().Add(f.life), name), nil
}

func (f *fakeIssuer) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) }

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func newManager(t *testing.T, iss Issuer) (*CertManager, *clock) {
	t.Helper()
	clk := &clock{now: time.Now()}
	return &CertManager{Store: CertStore{Dir: t.TempDir()}, Issuer: iss, Now: clk.Now,
		Owners: map[string]string{"a.example.org": "host-a", "b.example.org": "host-b"}}, clk
}

func TestMissingCertificatesAreObtainedOnStart(t *testing.T) {
	f := &fakeIssuer{t: t, life: 90 * 24 * time.Hour}
	m, _ := newManager(t, f)
	m.RunOnce(context.Background())
	if f.count() != 2 {
		t.Fatalf("issued %d, want 2", f.count())
	}
	for name, owner := range m.Owners {
		p, err := m.Fetch(name)
		if err != nil || p.Name != name {
			t.Fatalf("%s: %v", name, err)
		}
		if rec := m.Store.LoadRecord(name); rec.LastResult != "ok" || rec.LastAttempt.IsZero() || owner == "" {
			t.Fatalf("%s: record %+v", name, rec)
		}
	}
	m.RunOnce(context.Background()) // nothing is due now
	if f.count() != 2 {
		t.Fatalf("a second run issued again: %d", f.count())
	}
}

func TestRenewalIsDueOnlyUnder30Days(t *testing.T) {
	now := time.Now()
	rec := CertRecord{}
	for _, c := range []struct {
		name    string
		have    bool
		left    time.Duration
		next    time.Time
		wantDue bool
	}{
		{"missing", false, 0, time.Time{}, true},
		{"fresh", true, 60 * 24 * time.Hour, time.Time{}, false},
		{"29 days", true, 29 * 24 * time.Hour, time.Time{}, true},
		{"30 days exactly is not yet due", true, 30 * 24 * time.Hour, time.Time{}, false},
		{"expired", true, -time.Hour, time.Time{}, true},
		{"due but backing off", true, 10 * 24 * time.Hour, now.Add(time.Hour), false},
		{"missing and backing off", false, 0, now.Add(time.Minute), false},
		{"backoff over", true, 10 * 24 * time.Hour, now.Add(-time.Second), true},
	} {
		rec.NextAttempt = c.next
		if got := Due(c.have, now.Add(c.left), rec, now); got != c.wantDue {
			t.Errorf("%s: Due=%v, want %v", c.name, got, c.wantDue)
		}
	}
}

func TestRenewsWhenClose(t *testing.T) {
	f := &fakeIssuer{t: t, life: 20 * 24 * time.Hour} // issues a certificate that is already due for renewal
	m, clk := newManager(t, f)
	m.Owners = map[string]string{"a.example.org": "host-a"}
	m.RunOnce(context.Background())
	if f.count() != 1 {
		t.Fatal(f.count())
	}
	clk.now = clk.now.Add(2 * time.Hour) // past the (no) backoff
	f.life = 90 * 24 * time.Hour
	m.RunOnce(context.Background())
	if f.count() != 2 {
		t.Fatalf("a certificate with 20 days left was not renewed: %d calls", f.count())
	}
	clk.now = clk.now.Add(2 * time.Hour)
	m.RunOnce(context.Background())
	if f.count() != 2 {
		t.Fatalf("a 90 day certificate was renewed: %d calls", f.count())
	}
}

func TestBackoffAfterFailure(t *testing.T) {
	f := &fakeIssuer{t: t, life: 90 * 24 * time.Hour, err: errors.New("dns timeout")}
	m, clk := newManager(t, f)
	m.Owners = map[string]string{"a.example.org": "host-a"}
	retry := m.RunOnce(context.Background())
	rec := m.Store.LoadRecord("a.example.org")
	if rec.LastResult != "error" || rec.LastError != "dns timeout" || rec.Failures != 1 {
		t.Fatalf("record %+v", rec)
	}
	if want := clk.now.Add(BackoffBase); !retry.Equal(want.UTC().Truncate(time.Second)) {
		t.Fatalf("retry at %v, want %v", retry, want)
	}
	clk.now = clk.now.Add(BackoffBase - time.Minute)
	m.RunOnce(context.Background())
	if f.count() != 1 {
		t.Fatal("tried again inside the backoff")
	}
	clk.now = clk.now.Add(2 * time.Minute)
	m.RunOnce(context.Background())
	if f.count() != 2 || m.Store.LoadRecord("a.example.org").Failures != 2 {
		t.Fatalf("calls=%d record=%+v", f.count(), m.Store.LoadRecord("a.example.org"))
	}
	// A new manager on the same store (a restart) still respects the stored backoff.
	m2 := &CertManager{Store: m.Store, Issuer: f, Owners: m.Owners, Now: clk.Now}
	m2.RunOnce(context.Background())
	if f.count() != 2 {
		t.Fatal("a restart reset the backoff")
	}
	// Success clears it.
	f.err = nil
	clk.now = clk.now.Add(BackoffMax)
	m2.RunOnce(context.Background())
	if rec := m.Store.LoadRecord("a.example.org"); rec.LastResult != "ok" || rec.Failures != 0 || !rec.NextAttempt.IsZero() {
		t.Fatalf("record %+v", rec)
	}
}

// blockingIssuer stands in for a crash in the middle of an attempt: it records what is on disk when the CA is called.
type blockingIssuer struct {
	store CertStore
	seen  CertRecord
}

func (b *blockingIssuer) Obtain(ctx context.Context, name string) (Bundle, error) {
	b.seen = b.store.LoadRecord(name)
	return Bundle{}, errors.New("process killed here")
}

func TestBackoffIsOnDiskBeforeTheCAIsCalled(t *testing.T) {
	m, clk := newManager(t, nil)
	m.Owners = map[string]string{"a.example.org": "host-a"}
	bi := &blockingIssuer{store: m.Store}
	m.Issuer = bi
	m.RunOnce(context.Background())
	if bi.seen.LastAttempt.IsZero() || !bi.seen.NextAttempt.After(clk.now) {
		t.Fatalf("record during the attempt: %+v", bi.seen)
	}
	// simulate the crash: the record as it was during the attempt is all that survives
	m.Store.SaveRecord("a.example.org", bi.seen)
	f := &fakeIssuer{t: t, life: 90 * 24 * time.Hour}
	m2 := &CertManager{Store: m.Store, Issuer: f, Owners: m.Owners, Now: clk.Now}
	m2.RunOnce(context.Background())
	if f.count() != 0 {
		t.Fatal("a restart after a crash mid-attempt tried again at once")
	}
	clk.now = clk.now.Add(BackoffBase + time.Minute)
	m2.RunOnce(context.Background())
	if f.count() != 1 {
		t.Fatal("did not try again after the backoff")
	}
}

func TestStatusMarksFailingAfterThreeAndIssuerState(t *testing.T) {
	s := CertStore{Dir: t.TempDir()}
	owners := map[string]string{"a.example.org": "host-a"}
	s.SaveRecord("a.example.org", CertRecord{LastResult: "error", Failures: AlertFailures - 1})
	if s.Status(owners)["a.example.org"].Failing {
		t.Fatal("failing after 2")
	}
	s.SaveRecord("a.example.org", CertRecord{LastResult: "error", Failures: AlertFailures})
	if !s.Status(owners)["a.example.org"].Failing {
		t.Fatal("not failing after 3")
	}
	s.SaveRecord("a.example.org", CertRecord{LastResult: "ok"})
	if s.Status(owners)["a.example.org"].Failing {
		t.Fatal("failing marker not cleared by success")
	}
	if s.IssuerState() != "disabled" {
		t.Fatal(s.IssuerState())
	}
	s.SetIssuerState(true)
	if s.IssuerState() != "enabled" {
		t.Fatal(s.IssuerState())
	}
	s.SetIssuerState(false)
	if s.IssuerState() != "disabled" {
		t.Fatal(s.IssuerState())
	}
}

func TestBackoffDelayDoublesAndCaps(t *testing.T) {
	want := []time.Duration{time.Hour, 2 * time.Hour, 4 * time.Hour, 8 * time.Hour, 12 * time.Hour, 12 * time.Hour, 12 * time.Hour}
	for i, w := range want {
		if got := BackoffDelay(i + 1); got != w {
			t.Errorf("failure %d: %v, want %v", i+1, got, w)
		}
	}
}

func TestBadIssuerOutputIsNotStored(t *testing.T) {
	m, _ := newManager(t, issuerFunc(func(name string) Bundle { return makeBundle(t, time.Now().Add(90*24*time.Hour), "other.example.org") }))
	m.Owners = map[string]string{"a.example.org": "host-a"}
	m.RunOnce(context.Background())
	if _, err := m.Fetch("a.example.org"); !errors.Is(err, errNoCert) {
		t.Fatalf("a certificate for the wrong name was stored: %v", err)
	}
	if rec := m.Store.LoadRecord("a.example.org"); rec.LastResult != "error" {
		t.Fatalf("%+v", rec)
	}
	// key and chain from different certificates
	m, _ = newManager(t, issuerFunc(func(name string) Bundle {
		a, b := makeBundle(t, time.Now().Add(90*24*time.Hour), name), makeBundle(t, time.Now().Add(90*24*time.Hour), name)
		return Bundle{Fullchain: a.Fullchain, Privkey: b.Privkey}
	}))
	m.Owners = map[string]string{"a.example.org": "host-a"}
	m.RunOnce(context.Background())
	if _, err := m.Fetch("a.example.org"); !errors.Is(err, errNoCert) {
		t.Fatalf("a mismatched key was stored: %v", err)
	}
}

type issuerFunc func(name string) Bundle

func (f issuerFunc) Obtain(ctx context.Context, name string) (Bundle, error) { return f(name), nil }

func TestFetchRefusesUnder7Days(t *testing.T) {
	m, clk := newManager(t, nil)
	name := "a.example.org"
	b := makeBundle(t, clk.now.Add(8*24*time.Hour), name)
	if err := m.Store.SaveBundle(name, b); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Fetch(name); err != nil {
		t.Fatalf("8 days left: %v", err)
	}
	clk.now = clk.now.Add(24*time.Hour + time.Minute) // 6d23h59m left
	if _, err := m.Fetch(name); !errors.Is(err, errTooOld) {
		t.Fatalf("under 7 days: %v", err)
	}
	if _, err := m.Fetch("b.example.org"); !errors.Is(err, errNoCert) {
		t.Fatalf("no certificate: %v", err)
	}
}

func TestStatusShowsNotAfterAndLastAttempt(t *testing.T) {
	f := &fakeIssuer{t: t, life: 90 * 24 * time.Hour}
	m, _ := newManager(t, f)
	m.RunOnce(context.Background())
	st := m.Store.Status(m.Owners)
	if s := st["a.example.org"]; s.Owner != "host-a" || s.NotAfter == nil || s.LastAttempt == nil || s.LastResult != "ok" {
		t.Fatalf("%+v", s)
	}
	f.err = errors.New("boom")
	m.Store.SaveRecord("b.example.org", CertRecord{LastResult: "error", LastError: "boom", Failures: 1})
	if s := m.Store.Status(m.Owners)["b.example.org"]; s.LastError != "boom" || s.Failures != 1 {
		t.Fatalf("%+v", s)
	}
}
