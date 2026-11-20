package agent

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/KazuhaHub/infra-hub/internal/agenttest"
	"github.com/KazuhaHub/infra-hub/internal/bundle"
	"github.com/KazuhaHub/infra-hub/internal/hubkey"
	"github.com/KazuhaHub/infra-hub/internal/hubtrust"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

// newAgent is an agent for the world's host that trusts the given hubs, in the order given.
func newAgent(t *testing.T, w *agenttest.World, mode string, hubs ...*agenttest.Hub) (*Agent, *clock) {
	t.Helper()
	var urls, pins []string
	for _, h := range hubs {
		urls = append(urls, h.URL)
		pins = append(pins, h.Pin)
	}
	return newAgentURLs(t, w, mode, urls, pins)
}

func newAgentURLs(t *testing.T, w *agenttest.World, mode string, urls, pins []string) (*Agent, *clock) {
	t.Helper()
	cfg, err := FromValues(map[string]string{
		"INFRA_AGENT_TOKEN":     agenttest.Token(t, pins, urls),
		"INFRA_AGENT_HOST":      agenttest.Host,
		"INFRA_AGENT_AGE_KEY":   w.AgeKeyPath,
		"INFRA_AGENT_SIGNERS":   w.SignersPath,
		"INFRA_AGENT_MODE":      mode,
		"INFRA_AGENT_STATE_DIR": w.StateDir,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	id, err := cfg.CheckFiles()
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(cfg, id)
	if err != nil {
		t.Fatal(err)
	}
	a.Ansible = w.Stub
	a.Out = io.Discard
	c := &clock{t: time.Now()}
	a.Now = c.now
	return a, c
}

func cycle(t *testing.T, a *Agent) Outcome {
	t.Helper()
	o, err := a.Cycle(context.Background())
	if err != nil {
		t.Fatalf("cycle: %v", err)
	}
	return o
}

func releases(t *testing.T, w *agenttest.World) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(w.StateDir, "releases"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func mustState(t *testing.T, w *agenttest.World) State {
	t.Helper()
	st, err := LoadState(w.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestVerifyMode(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	p := w.Publish(agenttest.Options{})
	a, _ := newAgent(t, w, ModeVerify, hub)

	o := cycle(t, a)
	if o.Result != ResultVerified || o.Hub != hub.URL || !o.Reported {
		t.Fatalf("outcome %+v", o)
	}
	if got := releases(t, w); len(got) != 1 || got[0] != p.Commit {
		t.Fatalf("releases %v", got)
	}
	if b, err := os.ReadFile(filepath.Join(w.StateDir, "releases", p.Commit, "infra", "marker")); err != nil || string(b) != "release 1\n" {
		t.Errorf("extracted marker %q, %v", b, err)
	}
	if runs := w.StubRuns(); len(runs) != 0 {
		t.Errorf("verify mode ran ansible: %v", runs)
	}
	st := mustState(t, w)
	if st.Verified == nil || st.Verified.Commit != p.Commit || st.Verified.Time.Unix() != p.Time || st.Applied != nil || st.LastResult != ResultVerified {
		t.Errorf("state %+v", st)
	}
	rep, ok := hub.Report(t)
	if !ok || rep.Result != "verified" || rep.AppliedCommit != "" || !strings.Contains(rep.Message, p.Commit[:12]) {
		t.Errorf("hub report %+v (%v)", rep, ok)
	}

	// The same bundle again: the hub answers 304 and nothing happens.
	o = cycle(t, a)
	if o.Result != ResultUnchanged {
		t.Fatalf("second cycle %+v", o)
	}
	if rep, _ := hub.Report(t); rep.Result != "unchanged" {
		t.Errorf("hub report %+v", rep)
	}
}

func TestApplyModeAndForwardOnly(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	p1 := w.Publish(agenttest.Options{})
	a, clk := newAgent(t, w, ModeApply, hub)

	o := cycle(t, a)
	if o.Result != ResultOK || o.AppliedCommit != p1.Commit {
		t.Fatalf("outcome %+v", o)
	}
	runs := w.StubRuns()
	if len(runs) != 1 {
		t.Fatalf("stub runs %v", runs)
	}
	parts := strings.Split(runs[0], "|")
	if parts[0] != filepath.Join(w.StateDir, "releases", p1.Commit, "infra") || parts[1] != "-i inventory/hosts.yml --limit web1 site.yml" || parts[2] != w.AgeKeyPath {
		t.Errorf("ansible ran as %q", runs[0])
	}
	st := mustState(t, w)
	if st.Applied == nil || st.Applied.Commit != p1.Commit || st.Applied.Time.Unix() != p1.Time || st.Applied.At.IsZero() {
		t.Errorf("state %+v", st)
	}
	if rep, _ := hub.Report(t); rep.Result != "ok" || rep.AppliedCommit != p1.Commit {
		t.Errorf("hub report %+v", rep)
	}

	// 304: nothing to do, no second run.
	if o := cycle(t, a); o.Result != ResultUnchanged || len(w.StubRuns()) != 1 {
		t.Fatalf("second cycle %+v, runs %v", o, w.StubRuns())
	}
	// Like infra-pull, the same commit is applied again once the last success is over 24 h old (the 304 path).
	clk.t = clk.t.Add(25 * time.Hour)
	if o := cycle(t, a); o.Result != ResultOK || len(w.StubRuns()) != 2 {
		t.Fatalf("after 25h %+v, runs %v", o, w.StubRuns())
	}

	// A bundle with an older statement time is ignored, with no error, no extraction and no apply.
	p2 := w.Publish(agenttest.Options{Time: p1.Time - 500})
	o = cycle(t, a)
	if o.Result != ResultUnchanged || len(w.StubRuns()) != 2 {
		t.Fatalf("older bundle: %+v, runs %v", o, w.StubRuns())
	}
	for _, r := range releases(t, w) {
		if r == p2.Commit {
			t.Errorf("the older bundle was extracted")
		}
	}
	if st := mustState(t, w); st.Applied.Commit != p1.Commit || st.Verified.Commit != p1.Commit {
		t.Errorf("state moved back: %+v", st)
	}
	// Equal time but another commit is not newer either.
	w.Publish(agenttest.Options{Time: p1.Time})
	if o := cycle(t, a); o.Result != ResultUnchanged || len(w.StubRuns()) != 2 {
		t.Fatalf("equal time: %+v", o)
	}

	// A newer one is applied, and only the newest three releases are kept.
	var last agenttest.Published
	for i := 0; i < 4; i++ {
		last = w.Publish(agenttest.Options{Time: p1.Time + int64(100*(i+1))})
		if o := cycle(t, a); o.Result != ResultOK || o.AppliedCommit != last.Commit {
			t.Fatalf("newer bundle %d: %+v", i, o)
		}
		time.Sleep(10 * time.Millisecond) // release order is by modification time
	}
	if got := releases(t, w); len(got) != KeepReleases {
		t.Errorf("kept %v, want %d releases", got, KeepReleases)
	}
	if _, err := os.Stat(ReleaseDir(w.StateDir, last.Commit)); err != nil {
		t.Errorf("the newest release is gone: %v", err)
	}
}

func TestRejectedBundles(t *testing.T) {
	cases := map[string]agenttest.Options{
		"wrong signature key": {OtherKey: true},
		"wrong namespace":     {Namespace: "infra-main"},
		"hash mismatch":       {WrongHash: true},
		"wrong repo":          {Repo: "Evil/infra"},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			w := agenttest.NewWorld(t)
			hub := w.StartHub()
			w.Publish(opts)
			a, _ := newAgent(t, w, ModeApply, hub)
			o := cycle(t, a)
			if o.Result != ResultRejected || !o.Reported {
				t.Fatalf("outcome %+v", o)
			}
			if got := releases(t, w); len(got) != 0 {
				t.Errorf("extracted: %v", got)
			}
			if runs := w.StubRuns(); len(runs) != 0 {
				t.Errorf("applied: %v", runs)
			}
			if st := mustState(t, w); st.Verified != nil || st.Applied != nil || st.LastResult != ResultRejected {
				t.Errorf("state %+v", st)
			}
			if rep, _ := hub.Report(t); rep.Result != "rejected" || rep.Message == "" {
				t.Errorf("hub report %+v", rep)
			}
		})
	}
}

// fakeHub is a TLS server that answers the bundle request with fixed bytes; it lets a test serve what the real hub never
// would (an archive with another member).
func fakeHub(t *testing.T, body []byte) (url, pin string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/bundle/") {
			rw.Header().Set("Content-Type", "application/octet-stream")
			rw.Write(body)
			return
		}
		http.NotFound(rw, r)
	}))
	srv.StartTLS()
	t.Cleanup(srv.Close)
	cert, err := x509.ParseCertificate(srv.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return srv.URL, hubtrust.Pin(cert)
}

func encryptTo(t *testing.T, id *age.X25519Identity, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	wr, err := age.Encrypt(&buf, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	wr.Write(plain)
	if err := wr.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type member struct {
	name string
	data []byte
	typ  byte
}

func makeTar(t *testing.T, ms ...member) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, m := range ms {
		typ := m.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: m.name, Typeflag: typ, Mode: 0o644, Size: int64(len(m.data)), Format: tar.FormatUSTAR}
		if typ != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(m.data); err != nil && h.Size != 0 {
			t.Fatal(err)
		}
	}
	tw.Close()
	return buf.Bytes()
}

func TestArchiveShapeIsEnforced(t *testing.T) {
	w := agenttest.NewWorld(t)
	w.Publish(agenttest.Options{})
	l, err := bundle.Load(context.Background(), w.MirrorRepo, bundle.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	st, sg, tb := member{name: "bundle", data: l.Files.Statement}, member{name: "bundle.sig", data: l.Files.Signature}, member{name: "bundle.tar.gz", data: l.Files.Tarball}
	cases := map[string][]member{
		"extra member":  {st, sg, tb, {name: "extra", data: []byte("x")}},
		"wrong order":   {sg, st, tb},
		"missing":       {st, sg},
		"renamed":       {st, sg, {name: "bundle.tar", data: l.Files.Tarball}},
		"nested name":   {st, sg, {name: "./bundle.tar.gz", data: l.Files.Tarball}},
		"symlink":       {st, sg, {name: "bundle.tar.gz", typ: tar.TypeSymlink}},
		"directory":     {st, sg, {name: "bundle.tar.gz", typ: tar.TypeDir}},
		"big statement": {{name: "bundle", data: bytes.Repeat([]byte("x"), bundle.MaxStatement+1)}, sg, tb},
	}
	for name, ms := range cases {
		t.Run(name, func(t *testing.T) {
			url, pin := fakeHub(t, encryptTo(t, w.AgeID, makeTar(t, ms...)))
			a, _ := newAgentURLs(t, w, ModeApply, []string{url}, []string{pin})
			o := cycle(t, a)
			if o.Result != ResultRejected {
				t.Fatalf("outcome %+v", o)
			}
			if got := releases(t, w); len(got) != 0 {
				t.Errorf("extracted: %v", got)
			}
			if runs := w.StubRuns(); len(runs) != 0 {
				t.Errorf("applied: %v", runs)
			}
		})
	}
	// Not for this host's key, and not age at all.
	other, _ := age.GenerateX25519Identity()
	for name, body := range map[string][]byte{
		"other key": encryptTo(t, other, makeTar(t, st, sg, tb)),
		"not age":   []byte("hello"),
	} {
		url, pin := fakeHub(t, body)
		a, _ := newAgentURLs(t, w, ModeApply, []string{url}, []string{pin})
		if o := cycle(t, a); o.Result != ResultRejected {
			t.Errorf("%s: %+v", name, o)
		}
	}
	// A truncated age stream is caught when the end is read.
	good := encryptTo(t, w.AgeID, makeTar(t, st, sg, tb))
	url, pin := fakeHub(t, good[:len(good)-40])
	a, _ := newAgentURLs(t, w, ModeApply, []string{url}, []string{pin})
	if o := cycle(t, a); o.Result != ResultRejected {
		t.Errorf("truncated: %+v", o)
	}
	// The intact one is accepted by the same fake hub: the harness itself is sound.
	url, pin = fakeHub(t, good)
	a, _ = newAgentURLs(t, w, ModeVerify, []string{url}, []string{pin})
	if o := cycle(t, a); o.Result != ResultVerified {
		t.Errorf("intact: %+v", o)
	}
}

func TestMaliciousTarballIsRejectedAfterTheSignature(t *testing.T) {
	// CI signs whatever it archived, so a hostile tarball with a valid signature must still be refused at extraction.
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	w.Publish(agenttest.Options{Tarball: gz(t, tarEntries(t, tent{name: "infra/ok", data: "x"}, tent{name: "../evil", data: "x"}))})
	a, _ := newAgent(t, w, ModeApply, hub)
	o := cycle(t, a)
	if o.Result != ResultRejected {
		t.Fatalf("outcome %+v", o)
	}
	if got := releases(t, w); len(got) != 0 {
		t.Errorf("leftovers: %v", got)
	}
	if runs := w.StubRuns(); len(runs) != 0 {
		t.Errorf("applied: %v", runs)
	}
	if st := mustState(t, w); st.Verified != nil {
		t.Errorf("verified: %+v", st)
	}
}

func TestFailedApplyKeepsStateAndRetries(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	p1 := w.Publish(agenttest.Options{})
	a, _ := newAgent(t, w, ModeApply, hub)
	if o := cycle(t, a); o.Result != ResultOK {
		t.Fatalf("first apply %+v", o)
	}

	w.FailStub(true)
	p2 := w.Publish(agenttest.Options{})
	o := cycle(t, a)
	if o.Result != ResultFailed || o.AppliedCommit != p1.Commit || !strings.Contains(o.Message, "status 3") {
		t.Fatalf("outcome %+v", o)
	}
	st := mustState(t, w)
	if st.Applied.Commit != p1.Commit || st.Verified.Commit != p2.Commit {
		t.Errorf("state after the failure: %+v / %+v", st.Applied, st.Verified)
	}
	if rep, _ := hub.Report(t); rep.Result != "failed" || rep.AppliedCommit != p1.Commit {
		t.Errorf("hub report %+v", rep)
	}
	// The hub answers 304 now, and the agent still retries the extracted release.
	if o := cycle(t, a); o.Result != ResultFailed || len(w.StubRuns()) != 3 {
		t.Fatalf("retry while failing: %+v, runs %d", o, len(w.StubRuns()))
	}
	w.FailStub(false)
	o = cycle(t, a)
	if o.Result != ResultOK || o.AppliedCommit != p2.Commit {
		t.Fatalf("retry: %+v", o)
	}
	if st := mustState(t, w); st.Applied.Commit != p2.Commit {
		t.Errorf("state %+v", st.Applied)
	}
}

func TestSwitchingFromVerifyToApply(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	p := w.Publish(agenttest.Options{})
	a, _ := newAgent(t, w, ModeVerify, hub)
	if o := cycle(t, a); o.Result != ResultVerified {
		t.Fatalf("%+v", o)
	}
	a.Cfg.Mode = ModeApply
	if o := cycle(t, a); o.Result != ResultOK || o.AppliedCommit != p.Commit {
		t.Fatalf("%+v", o)
	}
}

func TestHubFailover(t *testing.T) {
	w := agenttest.NewWorld(t)
	live := w.StartHub()
	empty := agenttest.NewWorld(t).StartHub() // answers 503 no_bundle: its mirror has nothing
	p := w.Publish(agenttest.Options{})
	dead := agenttest.DeadURL(t)

	// The first hub is down, the second has no bundle, the third serves it; the report goes to the one that served.
	a, _ := newAgentURLs(t, w, ModeApply, []string{dead, empty.URL, live.URL}, []string{live.Pin, empty.Pin})
	o := cycle(t, a)
	if o.Result != ResultOK || o.Hub != live.URL || o.AppliedCommit != p.Commit || !o.Reported {
		t.Fatalf("outcome %+v", o)
	}
	if rep, ok := live.Report(t); !ok || rep.Result != "ok" {
		t.Errorf("live hub report %+v", rep)
	}
	if _, ok := empty.Report(t); ok {
		t.Errorf("the hub that served nothing got the report")
	}
	if st := mustState(t, w); st.LastHub != live.URL {
		t.Errorf("last hub %q", st.LastHub)
	}
}

func TestReportFallsBackToAnotherHub(t *testing.T) {
	w := agenttest.NewWorld(t)
	live := w.StartHub()
	w.Publish(agenttest.Options{})
	// The hub that serves the bundle rejects the report (an agent that is not registered there would see the same).
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/report" || r.URL.Path == "/v1/challenge" {
			http.Error(rw, "no", http.StatusInternalServerError)
			return
		}
		// Forward the bundle request to the real hub through a pinned client.
		h, _ := NewHub(live.URL, []string{live.Pin})
		body, notMod, err := h.Bundle(r.Context(), agenttest.Host, "")
		if err != nil || notMod {
			http.Error(rw, "x", 502)
			return
		}
		rw.Write(body)
	}))
	srv.StartTLS()
	t.Cleanup(srv.Close)
	cert, _ := x509.ParseCertificate(srv.TLS.Certificates[0].Certificate[0])
	a, _ := newAgentURLs(t, w, ModeVerify, []string{srv.URL, live.URL}, []string{hubtrust.Pin(cert), live.Pin})
	o := cycle(t, a)
	if o.Result != ResultVerified || o.Hub != srv.URL || !o.Reported {
		t.Fatalf("outcome %+v", o)
	}
	if rep, ok := live.Report(t); !ok || rep.Result != "verified" {
		t.Errorf("the second hub did not get the report: %+v", rep)
	}
}

func TestWrongPinIsUnreachable(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	w.Publish(agenttest.Options{})
	otherKey, _ := hubkey.Generate()
	wrong, _ := hubkey.Pin(otherKey)
	a, _ := newAgentURLs(t, w, ModeApply, []string{hub.URL}, []string{wrong})
	o := cycle(t, a)
	if o.Result != ResultUnreachable || o.Reported {
		t.Fatalf("outcome %+v", o)
	}
	if _, ok := hub.Report(t); ok {
		t.Errorf("the hub with the wrong key received a report")
	}
	if len(releases(t, w)) != 0 || len(w.StubRuns()) != 0 {
		t.Errorf("something happened")
	}
	if st := mustState(t, w); st.LastResult != ResultUnreachable {
		t.Errorf("state %+v", st)
	}
}

func TestOnlyOneAgentAtATime(t *testing.T) {
	dir := t.TempDir()
	l, err := AcquireLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(dir); err == nil || !strings.Contains(err.Error(), "another infra-agent is running") {
		t.Fatalf("second lock: %v", err)
	}
	l.Close()
	l2, err := AcquireLock(dir)
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	l2.Close()
}

func TestCorruptStateIsNotReplaced(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	w.Publish(agenttest.Options{})
	a, _ := newAgent(t, w, ModeVerify, hub)
	if err := PrepareDir(w.StateDir); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(w.StateDir, "state.json"), []byte("{broken"), 0o600)
	if _, err := a.Cycle(context.Background()); err == nil || !strings.Contains(err.Error(), "does not parse") {
		t.Fatalf("err %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(w.StateDir, "state.json")); string(b) != "{broken" {
		t.Errorf("the state was overwritten")
	}
}

func TestNoncesAreNeverLogged(t *testing.T) {
	// The report path decrypts a nonce; it must reach the logger only in redacted form. Run a cycle with a logger that
	// records everything at debug level and look for any 64-hex string.
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	w.Publish(agenttest.Options{})
	a, _ := newAgent(t, w, ModeVerify, hub)
	var buf bytes.Buffer
	restore := captureLogs(&buf)
	defer restore()
	cycle(t, a)
	if hex64.MatchString(buf.String()) {
		t.Errorf("a 64 digit hex value (a nonce?) is in the log:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "cycle finished") {
		t.Errorf("nothing was logged:\n%s", buf.String())
	}
}

var _ = io.Discard
