package certs

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/atomicfile"
)

// Certificate lifecycle on the hub. The names come only from the config (rendered from the inventory);
// nothing a client sends can add one. Each name has exactly one owner host, the only host that may
// fetch it (`cert <name>` over the SSH server).

// NameRe: lower-case DNS names with at least two labels; no wildcards, no underscores, no path characters.
var NameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

const (
	// RenewBefore: a certificate with less time left than this is renewed.
	RenewBefore = 30 * 24 * time.Hour
	// MinServeRemaining: the hub refuses to serve a certificate with less time left than this, so the client keeps
	// the one it has and its own check (also 7 days) alerts.
	MinServeRemaining = 7 * 24 * time.Hour
	// CertInterval: how often every name is looked at.
	CertInterval = 12 * time.Hour
	// Backoff after a failed attempt: BackoffBase, doubled per consecutive failure, at most BackoffMax. The next
	// allowed attempt is stored on disk, so a restart loop cannot hammer the CA either.
	BackoffBase = time.Hour
	BackoffMax  = 12 * time.Hour
)

// Bundle is what an Issuer returns and what is stored and served: the leaf followed by its intermediates, and the
// private key of the leaf (both PEM).
type Bundle struct {
	Fullchain []byte `json:"fullchain"`
	Privkey   []byte `json:"privkey"`
}

// Issuer obtains a new certificate for exactly one name. The real one (acme.go) talks to an ACME CA; tests use a fake.
type Issuer interface {
	Obtain(ctx context.Context, name string) (Bundle, error)
}

// CertRecord is what the hub remembers about the attempts for one name (the certificate itself is in the bundle).
type CertRecord struct {
	LastAttempt time.Time `json:"last_attempt"`
	LastResult  string    `json:"last_result"` // "ok", "error", or "" before the first attempt
	LastError   string    `json:"last_error,omitempty"`
	Failures    int       `json:"failures"` // consecutive failed attempts
	NextAttempt time.Time `json:"next_attempt,omitempty"`
}

// CertStore keeps <dir>/<name>/bundle.json (one file, replaced atomically, so the chain and key always belong
// together) and <dir>/<name>/record.json.
type CertStore struct{ Dir string }

func (s CertStore) path(name, file string) string { return filepath.Join(s.Dir, name, file) }

func (s CertStore) SaveBundle(name string, b Bundle) error {
	if err := os.MkdirAll(filepath.Join(s.Dir, name), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(b)
	if err != nil {
		return err
	}
	return atomicfile.Write(s.path(name, "bundle.json"), data, 0o600)
}

// LoadBundle returns the stored bundle and the leaf's expiry; os.ErrNotExist when there is none.
func (s CertStore) LoadBundle(name string) (Bundle, time.Time, error) {
	data, err := os.ReadFile(s.path(name, "bundle.json"))
	if err != nil {
		return Bundle{}, time.Time{}, err
	}
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return Bundle{}, time.Time{}, fmt.Errorf("bundle of %s: %w", name, err)
	}
	notAfter, err := checkBundle(b, name)
	if err != nil {
		return Bundle{}, time.Time{}, fmt.Errorf("bundle of %s: %w", name, err)
	}
	return b, notAfter, nil
}

func (s CertStore) LoadRecord(name string) CertRecord {
	var r CertRecord
	if data, err := os.ReadFile(s.path(name, "record.json")); err == nil {
		json.Unmarshal(data, &r)
	}
	return r
}

func (s CertStore) SaveRecord(name string, r CertRecord) error {
	if err := os.MkdirAll(filepath.Join(s.Dir, name), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(s.path(name, "record.json"), append(data, '\n'), 0o600)
}

// checkBundle verifies what the hub is about to store or serve: a leaf for name (SAN, not the common name) whose
// key is the given private key. It returns the leaf's expiry.
func checkBundle(b Bundle, name string) (time.Time, error) {
	pair, err := tls.X509KeyPair(b.Fullchain, b.Privkey)
	if err != nil {
		return time.Time{}, fmt.Errorf("chain and key do not form a pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return time.Time{}, err
	}
	if err := leaf.VerifyHostname(name); err != nil {
		return time.Time{}, fmt.Errorf("certificate is not for %s", name)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != name {
		return time.Time{}, fmt.Errorf("certificate must be for exactly %s", name)
	}
	if len(pair.Certificate) < 2 {
		return time.Time{}, errors.New("fullchain has no intermediate")
	}
	if block, _ := pem.Decode(b.Fullchain); block == nil || block.Type != "CERTIFICATE" {
		return time.Time{}, errors.New("fullchain is not PEM")
	}
	return leaf.NotAfter.UTC(), nil
}

// CertManager obtains missing certificates and renews those that are close to expiry.
type CertManager struct {
	Store  CertStore
	Issuer Issuer
	// Owners maps certificate name to the one host allowed to fetch it. The set of keys is the allow list of names.
	Owners map[string]string
	Now    func() time.Time

	mu sync.Mutex
}

func (m *CertManager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *CertManager) names() []string {
	names := make([]string, 0, len(m.Owners))
	for n := range m.Owners {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// BackoffDelay is the wait after the failures-th consecutive failure (1-based).
func BackoffDelay(failures int) time.Duration {
	d := BackoffBase
	for i := 1; i < failures && d < BackoffMax; i++ {
		d *= 2
	}
	if d > BackoffMax {
		d = BackoffMax
	}
	return d
}

// Due says whether an attempt should be made for a name now: the certificate is missing or has less than
// RenewBefore left, and the backoff from earlier failures has passed.
func Due(have bool, notAfter time.Time, rec CertRecord, now time.Time) bool {
	if have && notAfter.Sub(now) >= RenewBefore {
		return false
	}
	return !now.Before(rec.NextAttempt)
}

// RunOnce looks at every name once, in name order, one attempt at a time. It returns the earliest time at which a
// name that still needs an attempt may be tried (zero if none does).
func (m *CertManager) RunOnce(ctx context.Context) time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	var retryAt time.Time
	for _, name := range m.names() {
		if ctx.Err() != nil {
			return retryAt
		}
		_, notAfter, err := m.Store.LoadBundle(name)
		have := err == nil
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("cert %s: stored bundle unusable, will obtain a new one: %v", name, err)
		}
		rec := m.Store.LoadRecord(name)
		now := m.now()
		if !Due(have, notAfter, rec, now) {
			if (!have || notAfter.Sub(now) < RenewBefore) && now.Before(rec.NextAttempt) {
				if retryAt.IsZero() || rec.NextAttempt.Before(retryAt) {
					retryAt = rec.NextAttempt
				}
			}
			continue
		}
		// Record the attempt and its backoff before calling the CA: a crash or restart in the middle must still wait.
		started := now.UTC().Truncate(time.Second)
		pending := rec
		pending.LastAttempt = started
		pending.NextAttempt = now.Add(BackoffDelay(rec.Failures + 1)).UTC().Truncate(time.Second)
		if err := m.Store.SaveRecord(name, pending); err != nil {
			log.Printf("cert %s: cannot record the attempt, not trying: %v", name, err)
			continue
		}
		b, err := m.Issuer.Obtain(ctx, name)
		if err == nil {
			notAfter, err = checkBundle(b, name)
		}
		if err == nil {
			err = m.Store.SaveBundle(name, b)
		}
		now = m.now()
		rec.LastAttempt = now.UTC().Truncate(time.Second)
		if err != nil {
			rec.LastResult, rec.LastError = "error", err.Error()
			rec.Failures++
			rec.NextAttempt = now.Add(BackoffDelay(rec.Failures)).UTC().Truncate(time.Second)
			log.Printf("cert %s: attempt failed (%d in a row), next try after %s: %v", name, rec.Failures, rec.NextAttempt.Format(time.RFC3339), err)
			if retryAt.IsZero() || rec.NextAttempt.Before(retryAt) {
				retryAt = rec.NextAttempt
			}
		} else {
			rec.LastResult, rec.LastError, rec.Failures, rec.NextAttempt = "ok", "", 0, time.Time{}
			log.Printf("cert %s: issued, expires %s", name, notAfter.Format(time.RFC3339))
		}
		if serr := m.Store.SaveRecord(name, rec); serr != nil {
			log.Printf("cert %s: cannot save record: %v", name, serr)
		}
	}
	return retryAt
}

// Run calls RunOnce at start and then every CertInterval, or earlier when a backoff ends before that.
func (m *CertManager) Run(ctx context.Context) {
	for {
		retryAt := m.RunOnce(ctx)
		wait := CertInterval
		if !retryAt.IsZero() {
			if d := retryAt.Sub(m.now()); d < wait {
				wait = d
			}
			if wait < time.Minute {
				wait = time.Minute
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// CertSource is what the SSH server needs: who owns a name and the bundle to serve.
type CertSource interface {
	Owner(name string) (host string, ok bool)
	Fetch(name string) (CertPayload, error)
}

// CertPayload is the whole output of the `cert <name>` command: one JSON object on one line.
type CertPayload struct {
	Name      string `json:"name"`
	Fullchain string `json:"fullchain"`
	Privkey   string `json:"privkey"`
	NotAfter  string `json:"not_after"` // RFC 3339, UTC
}

func (m *CertManager) Owner(name string) (string, bool) {
	h, ok := m.Owners[name]
	return h, ok
}

var (
	errNoCert  = errors.New("no certificate yet")
	errTooOld  = errors.New("certificate has less than 7 days left")
	errBadCert = errors.New("stored certificate is unusable")
)

// Fetch returns the stored certificate for name, unless there is none or it expires within MinServeRemaining.
func (m *CertManager) Fetch(name string) (CertPayload, error) {
	b, notAfter, err := m.Store.LoadBundle(name)
	if errors.Is(err, os.ErrNotExist) {
		return CertPayload{}, errNoCert
	}
	if err != nil {
		log.Printf("cert %s: %v", name, err)
		return CertPayload{}, errBadCert
	}
	if notAfter.Sub(m.now()) < MinServeRemaining {
		return CertPayload{}, errTooOld
	}
	return CertPayload{Name: name, Fullchain: string(b.Fullchain), Privkey: string(b.Privkey), NotAfter: notAfter.Format(time.RFC3339)}, nil
}

// AlertFailures: a certificate that has failed this many attempts in a row is reported as failing in `infra-hub status`.
const AlertFailures = 3

// CertStatus is one entry of `infra-hub status`.
type CertStatus struct {
	Owner       string  `json:"owner"`
	NotAfter    *string `json:"not_after"`
	LastAttempt *string `json:"last_attempt"`
	LastResult  string  `json:"last_result"`
	LastError   string  `json:"last_error,omitempty"`
	Failures    int     `json:"failures"`
	// Failing is the marker a monitor reads: AlertFailures or more attempts failed in a row. It clears on success.
	Failing     bool    `json:"failing"`
	NextAttempt *string `json:"next_attempt,omitempty"`
}

// Status reads the store (not the running process), so `infra-hub status` works while the hub runs.
func (s CertStore) Status(owners map[string]string) map[string]CertStatus {
	out := map[string]CertStatus{}
	ts := func(t time.Time) *string {
		if t.IsZero() {
			return nil
		}
		v := t.UTC().Format(time.RFC3339)
		return &v
	}
	for name, owner := range owners {
		rec := s.LoadRecord(name)
		st := CertStatus{Owner: owner, LastAttempt: ts(rec.LastAttempt), LastResult: rec.LastResult, LastError: rec.LastError,
			Failures: rec.Failures, Failing: rec.Failures >= AlertFailures, NextAttempt: ts(rec.NextAttempt)}
		if _, na, err := s.LoadBundle(name); err == nil {
			st.NotAfter = ts(na)
		}
		out[name] = st
	}
	return out
}

// SetIssuerState records, for `infra-hub status`, whether the running hub can issue (it has a Cloudflare token).
func (s CertStore) SetIssuerState(enabled bool) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	v := "disabled\n"
	if enabled {
		v = "enabled\n"
	}
	return atomicfile.Write(filepath.Join(s.Dir, "issuer"), []byte(v), 0o600)
}

// IssuerState is "enabled" or "disabled" (also when the hub has never recorded it).
func (s CertStore) IssuerState() string {
	if data, err := os.ReadFile(filepath.Join(s.Dir, "issuer")); err == nil && strings.TrimSpace(string(data)) == "enabled" {
		return "enabled"
	}
	return "disabled"
}
