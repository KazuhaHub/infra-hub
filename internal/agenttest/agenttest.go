// Package agenttest is the test bench of infra-agent: a throwaway signing key, an infra repository whose commits are
// turned into bundles exactly as the CI of KazuhaHub/infra does it (git archive, a statement, ssh-keygen -Y sign), a
// git mirror holding main-attestation, real hub servers (internal/httpsapi over TLS 1.3 with a pinned identity key),
// and an ansible-playbook stub.
package agenttest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/KazuhaHub/infra-hub/internal/bundle"
	"github.com/KazuhaHub/infra-hub/internal/certs"
	"github.com/KazuhaHub/infra-hub/internal/httpsapi"
	"github.com/KazuhaHub/infra-hub/internal/hubkey"
	"github.com/KazuhaHub/infra-hub/internal/jointoken"
	"github.com/KazuhaHub/infra-hub/internal/state"
	"github.com/KazuhaHub/infra-hub/internal/testutil"
)

// Host is the host name of the test machine.
const Host = "web1"

// World is everything one test needs.
type World struct {
	T            *testing.T
	Dir          string
	AgeID        *age.X25519Identity
	AgeKeyPath   string
	SignersPath  string
	StateDir     string
	Stub         string // the ansible-playbook stub
	StubLog      string // one line per run: directory|arguments|SOPS_AGE_KEY_FILE
	StubFail     string // while this file exists the stub exits 3
	MirrorRepo   string // the git directory the hubs read bundles from
	signKey      string
	otherKey     string
	infra, attst string // work trees
	n            int
	published    map[string][3][]byte // commit -> statement, signature, tarball, for Republish
	// Certs, when set before a hub is started, is what the hub serves under /v1/cert.
	Certs certs.CertSource
}

// StaticCerts is a certificate source with fixed content: every name in Owners is served to its owner with Payload
// (whose Name is filled in), unless Err is set.
type StaticCerts struct {
	Owners  map[string]string
	Payload certs.CertPayload
	Err     error
}

func (s *StaticCerts) Owner(name string) (string, bool) { h, ok := s.Owners[name]; return h, ok }

func (s *StaticCerts) Fetch(name string) (certs.CertPayload, error) {
	if s.Err != nil {
		return certs.CertPayload{}, s.Err
	}
	p := s.Payload
	p.Name = name
	return p, nil
}

// Options shape one published bundle.
type Options struct {
	Time      int64             // statement time; 0 means later than the previous bundle
	Files     map[string]string // extra files of the infra tree
	Namespace string            // signature namespace (default infra-bundle)
	OtherKey  bool              // sign with a key that is not in allowed_signers
	WrongHash bool              // the statement carries the hash of other bytes
	Repo      string            // statement repo (default KazuhaHub/infra)
	Tarball   []byte            // use these bytes as bundle.tar.gz instead of git archive (signed all the same)
}

// Published is what Publish made.
type Published struct {
	Commit string
	Time   int64
}

func run(t *testing.T, dir, name string, stdin []byte, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

// NewWorld builds the bench. It skips the test when git or ssh-keygen is missing.
func NewWorld(t *testing.T) *World {
	t.Helper()
	testutil.NeedTool(t, "git", "ssh-keygen")
	w := &World{T: t, Dir: t.TempDir()}
	d := w.Dir
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	w.AgeID = id
	w.AgeKeyPath = filepath.Join(d, "age.key")
	must(t, os.WriteFile(w.AgeKeyPath, []byte("# created: test\n"+id.String()+"\n"), 0o600))
	w.signKey, w.otherKey = filepath.Join(d, "ci"), filepath.Join(d, "other")
	for _, k := range []string{w.signKey, w.otherKey} {
		run(t, d, "ssh-keygen", nil, "-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", k)
	}
	pub, err := os.ReadFile(w.signKey + ".pub")
	must(t, err)
	w.SignersPath = filepath.Join(d, "allowed_signers")
	must(t, os.WriteFile(w.SignersPath, []byte(`infra-main namespaces="infra-main,infra-bundle" `+string(pub)), 0o600))
	w.StateDir = filepath.Join(d, "state")
	w.infra, w.attst = filepath.Join(d, "infra"), filepath.Join(d, "attest")
	for _, p := range []string{w.infra, w.attst} {
		must(t, os.MkdirAll(p, 0o755))
		testutil.RunGit(t, p, "init", "-q", "-b", "main", ".")
	}
	testutil.RunGit(t, w.attst, "checkout", "-q", "--orphan", "main-attestation")
	w.MirrorRepo = filepath.Join(w.attst, ".git")
	w.StubLog, w.StubFail = filepath.Join(d, "ansible.log"), filepath.Join(d, "ansible.fail")
	w.Stub = filepath.Join(d, "ansible-playbook")
	script := fmt.Sprintf("#!/bin/sh\necho \"$PWD|$*|$SOPS_AGE_KEY_FILE\" >> %q\n[ -e %q ] && exit 3\nexit 0\n", w.StubLog, w.StubFail)
	must(t, os.WriteFile(w.Stub, []byte(script), 0o755))
	return w
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// Publish makes a new commit in the infra repository, builds its bundle and commits the three files to main-attestation.
func (w *World) Publish(o Options) Published {
	t := w.T
	t.Helper()
	w.n++
	files := map[string]string{
		"site.yml":                  "- hosts: all\n  tasks: []\n",
		"inventory/hosts.yml":       "all:\n  hosts:\n    web1:\n",
		"marker":                    fmt.Sprintf("release %d\n", w.n),
		"features/hello/README.txt": "hello\n",
	}
	for k, v := range o.Files {
		files[k] = v
	}
	for name, content := range files {
		p := filepath.Join(w.infra, name)
		must(t, os.MkdirAll(filepath.Dir(p), 0o755))
		must(t, os.WriteFile(p, []byte(content), 0o644))
	}
	testutil.RunGit(t, w.infra, "add", "-A")
	testutil.RunGit(t, w.infra, "commit", "-q", "-m", fmt.Sprintf("release %d", w.n))
	commit := testutil.RunGit(t, w.infra, "rev-parse", "HEAD")
	tgz := filepath.Join(w.Dir, "bundle.tar.gz")
	run(t, w.infra, "git", nil, "archive", "--format=tar.gz", "--prefix=infra/", "-o", tgz, commit)
	tarball, err := os.ReadFile(tgz)
	must(t, err)
	if o.Tarball != nil {
		tarball = o.Tarball
	}
	tm := o.Time
	if tm == 0 {
		tm = 1790000000 + int64(w.n)*100
	}
	sum := sha256.Sum256(tarball)
	if o.WrongHash {
		sum = sha256.Sum256(append([]byte("other"), tarball...))
	}
	repo := o.Repo
	if repo == "" {
		repo = "KazuhaHub/infra"
	}
	stmt := bundle.Statement{Repo: repo, Ref: "refs/heads/main", Commit: commit, Time: tm, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(tarball))}.String()
	ns, key := o.Namespace, w.signKey
	if ns == "" {
		ns = "infra-bundle"
	}
	if o.OtherKey {
		key = w.otherKey
	}
	stmtPath := filepath.Join(w.Dir, "bundle")
	must(t, os.WriteFile(stmtPath, []byte(stmt), 0o644))
	os.Remove(stmtPath + ".sig")
	run(t, w.Dir, "ssh-keygen", nil, "-Y", "sign", "-n", ns, "-f", key, stmtPath)
	sig, err := os.ReadFile(stmtPath + ".sig")
	must(t, err)
	must(t, os.WriteFile(filepath.Join(w.attst, "bundle"), []byte(stmt), 0o644))
	must(t, os.WriteFile(filepath.Join(w.attst, "bundle.sig"), sig, 0o644))
	must(t, os.WriteFile(filepath.Join(w.attst, "bundle.tar.gz"), tarball, 0o644))
	if w.published == nil {
		w.published = map[string][3][]byte{}
	}
	w.published[commit] = [3][]byte{[]byte(stmt), sig, tarball}
	w.commitAttestation([]byte(stmt), sig, tarball)
	return Published{Commit: commit, Time: tm}
}

func (w *World) commitAttestation(stmt, sig, tarball []byte) {
	t := w.T
	must(t, os.WriteFile(filepath.Join(w.attst, "bundle"), stmt, 0o644))
	must(t, os.WriteFile(filepath.Join(w.attst, "bundle.sig"), sig, 0o644))
	must(t, os.WriteFile(filepath.Join(w.attst, "bundle.tar.gz"), tarball, 0o644))
	testutil.RunGit(t, w.attst, "add", "-A")
	testutil.RunGit(t, w.attst, "commit", "-q", "--allow-empty", "-m", "attest")
}

// Republish serves an earlier bundle again, byte for byte (a replay of what CI once signed).
func (w *World) Republish(commit string) {
	w.T.Helper()
	f, ok := w.published[commit]
	if !ok {
		w.T.Fatalf("no bundle for %s", commit)
	}
	w.commitAttestation(f[0], f[1], f[2])
}

// StubRuns is how many times the ansible stub ran, and its log lines.
func (w *World) StubRuns() []string {
	data, err := os.ReadFile(w.StubLog)
	if err != nil || len(data) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

// FailStub makes the stub exit 3 (or, with false, exit 0) from now on.
func (w *World) FailStub(fail bool) {
	if fail {
		must(w.T, os.WriteFile(w.StubFail, nil, 0o644))
	} else {
		os.Remove(w.StubFail)
	}
}

// Hub is a real hub server on 127.0.0.1.
type Hub struct {
	URL, Pin string
	// Addr is the host:port the hub listens on; StartHubKey can take it over after Stop.
	Addr   string
	store  *state.State
	path   string
	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// StartHub serves the world's mirror for the world's host over TLS 1.3 with a fresh identity key.
func (w *World) StartHub() *Hub { return w.startHub(w.MirrorRepo, nil, "127.0.0.1:0") }

// StartHubKey is StartHub with the given identity key, listening on addr ("127.0.0.1:0" for any port). Giving the
// address of a stopped hub is a hub that comes back with another key at the same URL, as in a key rotation.
func (w *World) StartHubKey(key *ecdsa.PrivateKey, addr string) *Hub {
	return w.startHub(w.MirrorRepo, key, addr)
}

// StartHubEmpty is a hub for the same host whose mirror holds no bundle: it answers 503 no_bundle but takes reports.
func (w *World) StartHubEmpty() *Hub {
	dir := filepath.Join(w.Dir, fmt.Sprintf("empty-%d", time.Now().UnixNano()))
	must(w.T, os.MkdirAll(dir, 0o755))
	testutil.RunGit(w.T, dir, "init", "-q", "-b", "main", ".")
	return w.startHub(filepath.Join(dir, ".git"), nil, "127.0.0.1:0")
}

func (w *World) startHub(mirror string, key *ecdsa.PrivateKey, addr string) *Hub {
	t := w.T
	t.Helper()
	var err error
	if key == nil {
		key, err = hubkey.Generate()
		must(t, err)
	}
	pin, err := hubkey.Pin(key)
	must(t, err)
	cert, err := hubkey.Certificate(key, []string{"127.0.0.1"}, time.Now())
	must(t, err)
	h := &Hub{Pin: pin, path: filepath.Join(w.Dir, fmt.Sprintf("hub-state-%d.json", time.Now().UnixNano()))}
	h.store, err = state.LoadState(h.path)
	must(t, err)
	srv := httpsapi.NewServer(map[string]age.Recipient{Host: w.AgeID.Recipient()}, h.store)
	// A clock that moves 10 s at every look keeps the rate limiters from throttling a test that runs many cycles (the
	// nonce lifetime of 5 minutes still covers the few looks between a challenge and its report).
	var ticks atomic.Int64
	base := time.Now()
	srv.Now = func() time.Time { return base.Add(time.Duration(ticks.Add(1)) * 10 * time.Second) }
	srv.Bundles = &httpsapi.Bundles{Repo: mirror}
	srv.Certs = w.Certs
	ln, err := net.Listen("tcp", addr)
	must(t, err)
	h.Addr = ln.Addr().String()
	h.URL = "https://" + h.Addr
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel, h.done = cancel, make(chan struct{})
	go func() {
		defer close(h.done)
		_ = srv.Serve(ctx, ln, httpsapi.TLSConfig(func() *tls.Certificate { return cert }))
	}()
	t.Cleanup(h.Stop)
	return h
}

// Stop shuts the hub down.
func (h *Hub) Stop() {
	h.cancel()
	<-h.done
}

// Report is the latest report the hub holds for the host, read back from its state file (what `infra-hub status`
// shows as hosts[].report).
func (h *Hub) Report(t *testing.T) (state.HostReport, bool) {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	must(t, h.store.Flush())
	st, err := state.LoadState(h.path)
	must(t, err)
	r, ok := st.Reports()[Host]
	return r, ok
}

// DeadURL is the address of a hub that is down: a port nothing listens on.
func DeadURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	addr := ln.Addr().String()
	ln.Close()
	return "https://" + addr
}

// Token is the join token for the pins and hub URLs.
func Token(t *testing.T, pins, hubs []string) string {
	t.Helper()
	tok, err := jointoken.Encode(pins, hubs)
	must(t, err)
	return tok
}
