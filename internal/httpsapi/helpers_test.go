package httpsapi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/KazuhaHub/infra-hub/internal/hubca"
	"github.com/KazuhaHub/infra-hub/internal/state"
)

var t0 = time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)

// pki is a CA, a hub key and a signed hub certificate in a temp directory.
type pki struct {
	dir                       string
	caCert                    *x509.Certificate
	caKey                     *ecdsa.PrivateKey
	caPath, certPath, keyPath string
	key                       *ecdsa.PrivateKey
	addresses                 []string
}

func newPKI(t *testing.T, addresses ...string) *pki {
	t.Helper()
	if len(addresses) == 0 {
		addresses = []string{"127.0.0.1", "hub.example.org"}
	}
	p := &pki{dir: t.TempDir(), addresses: addresses}
	if _, err := hubca.Init(filepath.Join(p.dir, "ca"), t0, hubca.Constraints{}); err != nil {
		t.Fatal(err)
	}
	p.caPath = filepath.Join(p.dir, "ca", hubca.CertFile)
	var err error
	if p.caCert, err = hubca.ReadCertificate(p.caPath); err != nil {
		t.Fatal(err)
	}
	if p.caKey, err = hubca.ReadPrivateKey(filepath.Join(p.dir, "ca", hubca.KeyFile)); err != nil {
		t.Fatal(err)
	}
	p.keyPath = filepath.Join(p.dir, "hub-https.key")
	if p.key, err = LoadOrCreateKey(p.keyPath); err != nil {
		t.Fatal(err)
	}
	p.certPath = filepath.Join(p.dir, "hub.crt")
	p.sign(t, p.certPath, p.caKey, p.caCert, p.key, addresses)
	return p
}

// sign writes a certificate for key, signed by the given CA.
func (p *pki) sign(t *testing.T, out string, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, key *ecdsa.PrivateKey, names []string) {
	t.Helper()
	csr, err := hubca.NewCSR(key, names)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, _, err := hubca.Sign(hubca.SignOptions{CAKey: caKey, CACert: caCert, CSRPEM: csr, Now: t0})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}
}

// memStore is a ReportStore over a real State file.
type memStore struct {
	mu sync.Mutex
	st *state.State
}

func newStore(t *testing.T) (*memStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := state.LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	return &memStore{st: st}, path
}

func (m *memStore) SetReport(h string, r state.HostReport) { m.st.SetReport(h, r) }
func (m *memStore) Flush() error                           { return m.st.Flush() }

// testHub is a Server with a controllable clock and two hosts, h1 and h2, each with an age identity.
type testHub struct {
	s      *Server
	ids    map[string]*age.X25519Identity
	now    time.Time
	store  *memStore
	state  string
	client *http.Client
	base   string
}

func newHub(t *testing.T) *testHub {
	t.Helper()
	h := &testHub{ids: map[string]*age.X25519Identity{}, now: t0}
	rcpts := map[string]age.Recipient{}
	for _, name := range []string{"h1", "h2"} {
		id, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		h.ids[name] = id
		rcpts[name] = id.Recipient()
	}
	h.store, h.state = newStore(t)
	h.s = NewServer(rcpts, h.store)
	h.s.Now = func() time.Time { return h.now }
	return h
}

// do sends a request straight to the handler (the peer address is 192.0.2.1:1234).
func (h *testHub) do(t *testing.T, method, path, body string) (int, map[string]any) {
	t.Helper()
	return h.doFrom(t, "192.0.2.1:1234", method, path, strings.NewReader(body))
}

func (h *testHub) doFrom(t *testing.T, remote, method, path string, body io.Reader) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, "https://hub.example.org"+path, body)
	req.RemoteAddr = remote
	rec := &recorder{header: http.Header{}, code: 200}
	h.s.Handler().ServeHTTP(rec, req)
	var doc map[string]any
	if rec.body.Len() > 0 {
		if err := json.Unmarshal(rec.body.Bytes(), &doc); err != nil {
			t.Fatalf("%s %s: not JSON: %q", method, path, rec.body.String())
		}
	}
	if ct := rec.header.Get("Content-Type"); rec.body.Len() > 0 && ct != "application/json" {
		t.Errorf("content type %q", ct)
	}
	return rec.code, doc
}

type recorder struct {
	header http.Header
	code   int
	body   bytes.Buffer
}

func (r *recorder) Header() http.Header         { return r.header }
func (r *recorder) Write(b []byte) (int, error) { return r.body.Write(b) }
func (r *recorder) WriteHeader(c int)           { r.code = c }

// challenge asks for a challenge for host and decrypts it with the host's identity; it returns the nonce in hex.
func (h *testHub) challenge(t *testing.T, host string) string {
	t.Helper()
	code, doc := h.do(t, "POST", "/v1/challenge", `{"host":"`+host+`"}`)
	if code != 200 {
		t.Fatalf("challenge for %s: %d %v", host, code, doc)
	}
	return decryptChallenge(t, h.ids[host], doc["challenge"].(string))
}

func decryptChallenge(t *testing.T, id *age.X25519Identity, armored string) string {
	t.Helper()
	r, err := age.Decrypt(armor.NewReader(strings.NewReader(armored)), id)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	plain, err := io.ReadAll(r)
	if err != nil || len(plain) != 32 {
		t.Fatalf("plaintext %d bytes, %v", len(plain), err)
	}
	return nonceHex([32]byte(plain))
}

const commit = "0123456789abcdef0123456789abcdef01234567"

func reportBodyFor(host, nonce, report string) string {
	return `{"apiVersion":"v1","host":"` + host + `","nonce":"` + nonce + `","report":` + report + `}`
}

const goodReport = `{"appliedCommit":"` + commit + `","result":"ok","message":"applied","time":"2026-11-19T08:00:00Z","features":[{"name":"beszel-agent","result":"ok"},{"name":"hub","result":"skipped","message":"not this host"}]}`

func decryptWith(id *age.X25519Identity, armored string) ([]byte, error) {
	r, err := age.Decrypt(armor.NewReader(strings.NewReader(armored)), id)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func bigOne() *big.Int { return big.NewInt(1) }

func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
