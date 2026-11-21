package agent

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/tuf"

	"github.com/KazuhaHub/infra-hub/internal/agenttest"
	"github.com/KazuhaHub/infra-hub/internal/bundle"
	"github.com/KazuhaHub/infra-hub/internal/sigstorever"
	"github.com/KazuhaHub/infra-hub/internal/sigstorever/sigstoretest"
)

// sigAgent is an agent whose trusted root is the world's throwaway Sigstore.
func sigAgent(t *testing.T, w *agenttest.World, hubs ...*agenttest.Hub) *Agent {
	t.Helper()
	a, _ := newAgent(t, w, ModeVerify, hubs...)
	return a
}

func goodSigstore() *sigstoretest.Options { return &sigstoretest.Options{} }

func TestSigstoreModeAcceptsAValidBundle(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	// CI no longer produces bundle.sig: the Sigstore signature alone carries the bundle.
	p := w.Publish(agenttest.Options{NoSSH: true})
	a := sigAgent(t, w, hub)
	o := cycle(t, a)
	if o.Result != ResultVerified || o.Hub != hub.URL {
		t.Fatalf("outcome %+v", o)
	}
	st := mustState(t, w)
	if st.Verified == nil || st.Verified.Commit != p.Commit || st.Verified.Signature != SigSigstore {
		t.Errorf("state %+v", st.Verified)
	}
	if _, err := os.Stat(ReleaseDir(w.StateDir, p.Commit)); err != nil {
		t.Errorf("not extracted: %v", err)
	}
	// The next cycle is a 304.
	if o := cycle(t, a); o.Result != ResultUnchanged {
		t.Errorf("second cycle %+v", o)
	}
}

func TestSigstoreModeRejections(t *testing.T) {
	other := sigstoretest.New(t)
	const base = "https://github.com/KazuhaHub/infra/.github/workflows/"
	cases := []struct {
		name  string
		opts  agenttest.Options
		root  *sigstoretest.Fake // the agent's trusted root, when not the world's
		repo  string             // the agent's configured repository
		match string
	}{
		{"other repository", agenttest.Options{Sigstore: &sigstoretest.Options{Repo: "Evil/infra"}}, nil, "", "expected SAN"},
		{"other workflow", agenttest.Options{Sigstore: &sigstoretest.Options{Identity: base + "other.yml@refs/heads/main"}}, nil, "", "expected SAN"},
		{"feature branch", agenttest.Options{Sigstore: &sigstoretest.Options{Identity: base + "attest-main.yml@refs/heads/feature"}}, nil, "", "expected SAN"},
		{"wrong issuer", agenttest.Options{Sigstore: &sigstoretest.Options{Issuer: "https://accounts.google.com"}}, nil, "", "issuer"},
		{"digest mismatch", agenttest.Options{Sigstore: goodSigstore(), SigstoreOver: []byte("another statement")}, nil, "", "digest"},
		{"no transparency log entry", agenttest.Options{Sigstore: &sigstoretest.Options{NoTlog: true}}, nil, "", "does not verify"},
		{"unknown trusted root", agenttest.Options{Sigstore: goodSigstore()}, other, "", "does not verify"},
		{"not a bundle", agenttest.Options{SigstoreRaw: []byte("{}")}, nil, "", "not a valid Sigstore bundle"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := agenttest.NewWorld(t)
			hub := w.StartHub()
			w.Publish(c.opts) // a bundle.sig is there: nothing falls back to it
			a := sigAgent(t, w, hub)
			if c.root != nil {
				a.SigstoreRoot = c.root.TrustedMaterial()
			}
			o := cycle(t, a)
			if o.Result != ResultRejected {
				t.Fatalf("outcome %+v", o)
			}
			// The reason in full, from the check itself (the cycle's message is cut short).
			l, err := bundle.Load(context.Background(), w.MirrorRepo, bundle.DefaultLimits)
			if err != nil {
				t.Fatal(err)
			}
			_, err = a.verifyFiles(context.Background(), l.Files)
			var rj *RejectError
			if !errors.As(err, &rj) || !strings.Contains(rj.Reason, c.match) {
				t.Fatalf("reason %v, want one with %q", err, c.match)
			}
			if st := mustState(t, w); st.Verified != nil {
				t.Errorf("recorded %+v", st.Verified)
			}
			if got := releases(t, w); len(got) != 0 {
				t.Errorf("extracted %v", got)
			}
		})
	}
}

// A bundle that the hub serves without bundle.sigstore.json (an archive of format 1) fails verification with a clear reason.
func TestNoSigstoreFileIsRejected(t *testing.T) {
	w := agenttest.NewWorld(t)
	w.Publish(agenttest.Options{NoSigstore: true})
	l := bundle.Files{Statement: []byte("x"), Tarball: []byte("y")}
	a, _ := newAgentURLs(t, w, ModeVerify, []string{agenttest.DeadURL(t)}, []string{testPin})
	_, err := a.verifyFiles(context.Background(), l)
	var rj *RejectError
	if !errors.As(err, &rj) || !strings.Contains(rj.Reason, "no bundle.sigstore.json") {
		t.Fatalf("%v", err)
	}
}

func TestSigstoreIdentityFollowsTheConfiguredRepository(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	w.Publish(agenttest.Options{Repo: "Org/other-infra", Sigstore: &sigstoretest.Options{Repo: "Org/other-infra"}})
	a := sigAgent(t, w, hub)
	a.Cfg.Repo = "Org/other-infra"
	if o := cycle(t, a); o.Result != ResultVerified {
		t.Fatalf("%+v", o)
	}
	// The default repository's identity does not match a bundle signed for another one.
	w2 := agenttest.NewWorld(t)
	hub2 := w2.StartHub()
	w2.Publish(agenttest.Options{Repo: "Org/other-infra", Sigstore: &sigstoretest.Options{Repo: "KazuhaHub/infra"}})
	a2 := sigAgent(t, w2, hub2)
	a2.Cfg.Repo = "Org/other-infra"
	if o := cycle(t, a2); o.Result != ResultRejected {
		t.Fatalf("%+v", o)
	}
}

// Agents of v0.15.0 verify the Sigstore signature only. The legacy ssh signature may be there, be absent, or be
// garbage: it is never looked at, and a valid one does not save a bundle whose Sigstore signature is bad.
func TestTheSSHSignatureIsNeverConsulted(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	w.Publish(agenttest.Options{})
	if res := cycle(t, sigAgent(t, w, hub)); res.Result != ResultVerified {
		t.Fatalf("%+v", res)
	}
	if st := mustState(t, w); st.Verified.Signature != SigSigstore {
		t.Errorf("signature %q", st.Verified.Signature)
	}
	// A bad Sigstore signature next to a bundle.sig is a rejection.
	w2 := agenttest.NewWorld(t)
	hub2 := w2.StartHub()
	w2.Publish(agenttest.Options{Sigstore: &sigstoretest.Options{Repo: "Evil/infra"}})
	if res := cycle(t, sigAgent(t, w2, hub2)); res.Result != ResultRejected {
		t.Fatalf("%+v", res)
	}
}

// An agent that an older agent left a state with a bundle that was verified with the ssh signature asks again and
// refuses to apply it until it has been seen with its Sigstore signature.
func TestABundleVerifiedWithSSHIsCheckedAgain(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	p := w.Publish(agenttest.Options{})
	a := sigAgent(t, w, hub)
	if o := cycle(t, a); o.Result != ResultVerified {
		t.Fatalf("%+v", o)
	}
	st := mustState(t, w)
	st.Verified.Signature = SigSSH // what agents before v0.15.0 wrote
	if err := st.Save(w.StateDir); err != nil {
		t.Fatal(err)
	}
	// Same commit, same hub: a 304 would keep the ssh-verified bundle for good. The agent asks again.
	if o := cycle(t, a); o.Result != ResultUnchanged {
		t.Fatalf("%+v", o)
	}
	if st := mustState(t, w); st.Verified.Commit != p.Commit || st.Verified.Signature != SigSigstore {
		t.Errorf("state %+v", st.Verified)
	}
}

func TestAppliedRecordKeepsTheSignature(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	w.Publish(agenttest.Options{})
	a, _ := newAgent(t, w, ModeApply, hub)
	if o := cycle(t, a); o.Result != ResultOK {
		t.Fatalf("%+v", o)
	}
	if st := mustState(t, w); st.Applied == nil || st.Applied.Signature != SigSigstore {
		t.Errorf("state %+v", st.Applied)
	}
}

func TestSigstoreNeedsNoAllowedSigners(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	w.Publish(agenttest.Options{NoSSH: true})
	vals := map[string]string{
		"INFRA_AGENT_TOKEN":     agenttest.Token(t, []string{hub.Pin}, []string{hub.URL}),
		"INFRA_AGENT_HOST":      agenttest.Host,
		"INFRA_AGENT_AGE_KEY":   w.AgeKeyPath,
		"INFRA_AGENT_STATE_DIR": w.StateDir,
	}
	if _, err := FromValues(vals, nil); !isConfigError(err) || !strings.Contains(err.Error(), "SIGSTORE_REPO_ID is required") {
		t.Fatalf("without the IDs: %v", err)
	}
	vals["INFRA_AGENT_SIGSTORE_REPO_ID"], vals["INFRA_AGENT_SIGSTORE_OWNER_ID"] = "1462297697", "165913136"
	// The retired settings are accepted: a host that still has them keeps updating.
	vals["INFRA_AGENT_SIGNATURE"], vals["INFRA_AGENT_SIGNERS"] = "either", filepath.Join(w.Dir, "no-such-file")
	cfg, err := FromValues(vals, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SigstoreRepoID != "1462297697" || cfg.SigstoreOwnerID != "165913136" || len(cfg.Warnings) != 2 {
		t.Fatalf("config %+v", cfg)
	}
	id, err := cfg.CheckFiles()
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(cfg, id)
	if err != nil {
		t.Fatal(err)
	}
	a.SigstoreRoot = w.Sigstore.TrustedMaterial()
	a.Ansible, a.Out = w.Stub, nopWriter{}
	a.InfraLock, a.InfraApplied = filepath.Join(w.Dir, "infra", "lock"), filepath.Join(w.Dir, "infra-applied")
	if o := cycle(t, a); o.Result != ResultVerified {
		t.Fatalf("%+v", o)
	}
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

func archiveOf(t *testing.T, w *agenttest.World, format int) []byte {
	t.Helper()
	l, err := bundle.Load(context.Background(), w.MirrorRepo, bundle.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := bundle.Archive(l.Files, timeOf(l), format)
	if err != nil {
		t.Fatal(err)
	}
	return encryptTo(t, w.AgeID, plain)
}

// A hub of v0.14.0 knows formats up to 2 and answers a request for format 3 as format 2 (four members); the agent
// accepts that and so also a format 3 answer.
func TestAgentAcceptsTheAnswersOfOldAndNewHubs(t *testing.T) {
	w := agenttest.NewWorld(t)
	w.Publish(agenttest.Options{})
	for name, format := range map[string]int{"v0.14.0 hub (format 2)": bundle.Format2, "v0.15.0 hub (format 3)": bundle.Format3} {
		url, pin := fakeHub(t, archiveOf(t, w, format))
		a, _ := newAgentURLs(t, w, ModeVerify, []string{url}, []string{pin})
		if o := cycle(t, a); o.Result != ResultVerified {
			t.Errorf("%s: %+v", name, o)
		}
		os.RemoveAll(w.StateDir)
	}
	// A hub that answers in format 1 (three files, no Sigstore bundle) gives nothing to verify.
	url, pin := fakeHub(t, archiveOf(t, w, bundle.Format1))
	a, _ := newAgentURLs(t, w, ModeVerify, []string{url}, []string{pin})
	if o := cycle(t, a); o.Result != ResultRejected {
		t.Errorf("format 1: %+v", o)
	}
}

func TestAgentAlwaysRequestsFormat3(t *testing.T) {
	w := agenttest.NewWorld(t)
	var mu sync.Mutex
	var seen []string
	url, pin := fakeHubFunc(t, func(rw http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if strings.HasPrefix(r.URL.Path, "/v1/bundle/") {
			seen = append(seen, r.Header.Get(FormatHeader))
		}
		mu.Unlock()
		rw.WriteHeader(http.StatusServiceUnavailable)
	})
	a, _ := newAgentURLs(t, w, ModeVerify, []string{url}, []string{pin})
	a.Cfg.Warnings = []string{"legacy"} // legacy settings change nothing
	cycle(t, a)
	if got := strings.Join(seen, ","); got != "3" {
		t.Errorf("%s header values %q, want \"3\"", FormatHeader, got)
	}
}

func TestOpenBundleMembers(t *testing.T) {
	w := agenttest.NewWorld(t)
	w.Publish(agenttest.Options{})
	l, err := bundle.Load(context.Background(), w.MirrorRepo, bundle.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := newAgentURLs(t, w, ModeVerify, []string{agenttest.DeadURL(t)}, []string{testPin})
	st, sg, tb := member{name: "bundle", data: l.Files.Statement}, member{name: "bundle.sig", data: l.Files.Signature}, member{name: "bundle.tar.gz", data: l.Files.Tarball}
	ss := member{name: "bundle.sigstore.json", data: l.Files.Sigstore}
	open := func(ms ...member) (bundle.Files, error) {
		return OpenBundle(bytes.NewReader(encryptTo(t, w.AgeID, makeTar(t, ms...))), a.ID)
	}
	for name, ms := range map[string][]member{"three members (format 3)": {st, tb, ss}, "four members (format 2)": {st, sg, tb, ss}} {
		f, err := open(ms...)
		if err != nil || !bytes.Equal(f.Sigstore, l.Files.Sigstore) || !bytes.Equal(f.Statement, l.Files.Statement) || !bytes.Equal(f.Tarball, l.Files.Tarball) {
			t.Fatalf("%s: %v", name, err)
		}
		if f.Signature != nil {
			t.Errorf("%s: the legacy signature was kept", name)
		}
	}
	if f, err := open(st, sg, tb); err != nil || f.Sigstore != nil { // format 1: opens, then fails verification
		t.Fatalf("format 1: %v", err)
	}
	for name, ms := range map[string][]member{
		"five members":          {st, sg, tb, ss, ss},
		"sigstore before":       {st, sg, ss, tb},
		"sigstore before tar":   {st, ss, tb},
		"signature twice":       {st, sg, sg, tb, ss},
		"wrong last name":       {st, tb, {name: "bundle.sigstore", data: ss.data}},
		"last is a symlink":     {st, tb, {name: "bundle.sigstore.json", typ: tar.TypeSymlink}},
		"last is too large":     {st, tb, {name: "bundle.sigstore.json", data: bytes.Repeat([]byte("x"), bundle.MaxSigstore+1)}},
		"signature too large":   {st, {name: "bundle.sig", data: bytes.Repeat([]byte("x"), bundle.MaxSignature+1)}, tb, ss},
		"last then something":   {st, tb, ss, {name: "x", data: []byte("x")}},
		"no tarball":            {st, ss},
		"no statement":          {tb, ss},
		"something else second": {st, {name: "x", data: []byte("x")}, tb, ss},
	} {
		if _, err := open(ms...); err == nil {
			t.Errorf("%s: accepted", name)
		} else {
			var rj *RejectError
			if !errors.As(err, &rj) {
				t.Errorf("%s: %v is not a RejectError", name, err)
			}
		}
	}
}

func TestGitHubFallbackReadsTheSigstoreFile(t *testing.T) {
	w := agenttest.NewWorld(t)
	p := w.Publish(agenttest.Options{NoSSH: true})
	a := githubAgent(t, w, ModeVerify, w.MirrorRepo, agenttest.DeadURL(t))
	o := cycle(t, a)
	if o.Result != ResultVerified || o.Hub != GitHubSource {
		t.Fatalf("outcome %+v", o)
	}
	if st := mustState(t, w); st.Verified.Commit != p.Commit || st.Verified.Signature != SigSigstore {
		t.Errorf("state %+v", st.Verified)
	}
	// Without the file in the tree there is nothing to serve (the tree is not a bundle).
	w2 := agenttest.NewWorld(t)
	w2.Publish(agenttest.Options{NoSigstore: true})
	a = githubAgent(t, w2, ModeVerify, w2.MirrorRepo, agenttest.DeadURL(t))
	if o := cycle(t, a); o.Result == ResultVerified || strings.Contains(o.Message, "verified") {
		t.Fatalf("outcome %+v", o)
	}
}

func TestEmbeddedRootIsUsedWhenNothingIsInjected(t *testing.T) {
	w := agenttest.NewWorld(t)
	w.Publish(agenttest.Options{}) // signed by a throwaway Sigstore: the public-good root rejects it
	a, _ := newAgentURLs(t, w, ModeVerify, []string{agenttest.DeadURL(t)}, []string{testPin})
	a.SigstoreRoot = nil
	l, err := bundle.Load(context.Background(), w.MirrorRepo, bundle.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.verifyFiles(context.Background(), l.Files)
	var rj *RejectError
	if !errors.As(err, &rj) {
		t.Fatalf("%v", err)
	}
	if sigstorever.Identity(a.Cfg.Repo) == "" {
		t.Fatal("no identity")
	}
}

func timeOf(l bundle.Loaded) time.Time { return time.Unix(l.Statement.Time, 0) }

// The ssh signature that a state may carry is no longer enough to apply: a bundle that an older agent verified with it
// is not applied until it has been seen with its Sigstore signature.
func TestABundleVerifiedWithSSHIsNotApplied(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	p := w.Publish(agenttest.Options{})
	a, clk := newAgent(t, w, ModeApply, hub)
	if o := cycle(t, a); o.Result != ResultOK {
		t.Fatalf("%+v", o)
	}
	runs := len(w.StubRuns())
	st := mustState(t, w)
	st.Verified.Signature = SigSSH
	// Not yet due: nothing to do.
	if o := a.decide(context.Background(), &st, hub.URL, p.Commit, false); o.Result != ResultUnchanged {
		t.Fatalf("%+v", o)
	}
	// Due again after 24 h: the re-apply is refused, because the record says ssh (a record of an older agent has none).
	clk.t = clk.t.Add(25 * time.Hour)
	for _, sig := range []string{SigSSH, ""} {
		st.Verified.Signature = sig
		o := a.decide(context.Background(), &st, hub.URL, p.Commit, false)
		if o.Result != ResultRejected || !strings.Contains(o.Message, "refusing to apply") || len(w.StubRuns()) != runs {
			t.Fatalf("%q: %+v, runs %v", sig, o, w.StubRuns())
		}
	}
	// Seen with its Sigstore signature, the same bundle is applied.
	st.Verified.Signature = SigSigstore
	if o := a.decide(context.Background(), &st, hub.URL, p.Commit, false); o.Result != ResultOK || len(w.StubRuns()) != runs+1 {
		t.Fatalf("%+v", o)
	}
}

// The bundle that the real CI of KazuhaHub/infra made verifies through the agent with the embedded root and the strict
// policy (no test root, so nothing is relaxed); another repository or owner ID does not.
func TestRealCIBundleThroughTheAgent(t *testing.T) {
	read := func(n string) []byte {
		b, err := os.ReadFile(filepath.Join("..", "sigstorever", "testdata", n))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	files := bundle.Files{Statement: read("bundle"), Sigstore: read("bundle.sigstore.json")}
	w := agenttest.NewWorld(t)
	a, _ := newAgentURLs(t, w, ModeVerify, []string{agenttest.DeadURL(t)}, []string{testPin})
	a.SigstoreRoot = nil // the embedded root and the strict policy
	if sig, err := a.verifyFiles(context.Background(), files); err != nil || sig != SigSigstore {
		t.Fatalf("%q %v", sig, err)
	}
	for name, ids := range map[string][2]string{"repository ID": {"1", "165913136"}, "owner ID": {"1462297697", "1"}} {
		a.Cfg.SigstoreRepoID, a.Cfg.SigstoreOwnerID = ids[0], ids[1]
		_, err := a.verifyFiles(context.Background(), files)
		var rj *RejectError
		if !errors.As(err, &rj) || !strings.Contains(rj.Reason, "Identifier") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// When TUF cannot be reached after a cache existed, the report says that the embedded root was used, and it says so as a warning.
func TestEmbeddedRootFallbackIsInTheReport(t *testing.T) {
	read := func(n string) []byte {
		b, err := os.ReadFile(filepath.Join("..", "sigstorever", "testdata", n))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	files := bundle.Files{Statement: read("bundle"), Sigstore: read("bundle.sigstore.json")}
	w := agenttest.NewWorld(t)
	a, _ := newAgentURLs(t, w, ModeVerify, []string{agenttest.DeadURL(t)}, []string{testPin})
	a.SigstoreRoot = nil
	dir := filepath.Join(w.Dir, "tuf")
	base := "https://127.0.0.1:1"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := (&tuf.Config{LastTimestamp: time.Now().AddDate(0, 0, -3)}).Persist(filepath.Join(dir, tuf.URLToPath(base)+".json")); err != nil {
		t.Fatal(err)
	}
	a.SigstoreTUF = &sigstorever.Manager{Dir: dir, BaseURL: base}
	if err := PrepareDir(a.Cfg.StateDir); err != nil {
		t.Fatal(err)
	}
	if _, err := a.verifyFiles(context.Background(), files); err != nil {
		t.Fatal(err)
	}
	want := "WARNING sigstore root: embedded fallback (TUF unreachable since "
	if !strings.HasPrefix(a.rootNote, want) {
		t.Errorf("note %q", a.rootNote)
	}
}
