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

	"github.com/KazuhaHub/infra-hub/internal/agenttest"
	"github.com/KazuhaHub/infra-hub/internal/bundle"
	"github.com/KazuhaHub/infra-hub/internal/sigstorever"
	"github.com/KazuhaHub/infra-hub/internal/sigstorever/sigstoretest"
)

// sigAgent is newAgent with a signature mode and the world's throwaway Sigstore as the trusted root.
func sigAgent(t *testing.T, w *agenttest.World, sig string, hubs ...*agenttest.Hub) *Agent {
	t.Helper()
	a, _ := newAgent(t, w, ModeVerify, hubs...)
	a.Cfg.Signature = sig
	a.SigstoreRoot = w.Sigstore.TrustedMaterial()
	return a
}

func goodSigstore() *sigstoretest.Options { return &sigstoretest.Options{} }

func TestSigstoreModeAcceptsAValidBundle(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	// The ssh signature is by a key nobody trusts: only the Sigstore signature can carry this bundle.
	p := w.Publish(agenttest.Options{OtherKey: true, Sigstore: goodSigstore()})
	a := sigAgent(t, w, SigSigstore, hub)
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
		{"no file", agenttest.Options{}, nil, "", "no bundle.sigstore.json"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := agenttest.NewWorld(t)
			hub := w.StartHub()
			w.Publish(c.opts) // the ssh signature is valid: sigstore mode must not fall back to it
			a := sigAgent(t, w, SigSigstore, hub)
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

func TestSigstoreIdentityFollowsTheConfiguredRepository(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	w.Publish(agenttest.Options{Repo: "Org/other-infra", Sigstore: &sigstoretest.Options{Repo: "Org/other-infra"}})
	a := sigAgent(t, w, SigSigstore, hub)
	a.Cfg.Repo = "Org/other-infra"
	if o := cycle(t, a); o.Result != ResultVerified {
		t.Fatalf("%+v", o)
	}
	// The default repository's identity does not match a bundle signed for another one.
	w2 := agenttest.NewWorld(t)
	hub2 := w2.StartHub()
	w2.Publish(agenttest.Options{Repo: "Org/other-infra", Sigstore: &sigstoretest.Options{Repo: "KazuhaHub/infra"}})
	a2 := sigAgent(t, w2, SigSigstore, hub2)
	a2.Cfg.Repo = "Org/other-infra"
	if o := cycle(t, a2); o.Result != ResultRejected {
		t.Fatalf("%+v", o)
	}
}

func TestSSHModeIgnoresTheSigstoreFile(t *testing.T) {
	for name, o := range map[string]agenttest.Options{
		"valid":   {Sigstore: goodSigstore()},
		"garbage": {SigstoreRaw: []byte("garbage")},
		"wrong":   {Sigstore: &sigstoretest.Options{Repo: "Evil/infra"}},
	} {
		t.Run(name, func(t *testing.T) {
			w := agenttest.NewWorld(t)
			hub := w.StartHub()
			w.Publish(o)
			a := sigAgent(t, w, SigSSH, hub)
			if res := cycle(t, a); res.Result != ResultVerified {
				t.Fatalf("%+v", res)
			}
			if st := mustState(t, w); st.Verified.Signature != SigSSH {
				t.Errorf("signature %q", st.Verified.Signature)
			}
		})
	}
	// With an ssh signature that does not verify, a good Sigstore file does not help in ssh mode.
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	w.Publish(agenttest.Options{OtherKey: true, Sigstore: goodSigstore()})
	if res := cycle(t, sigAgent(t, w, SigSSH, hub)); res.Result != ResultRejected {
		t.Fatalf("%+v", res)
	}
}

func TestEitherMode(t *testing.T) {
	cases := []struct {
		name   string
		opts   agenttest.Options
		result string
		sig    string
	}{
		{"ssh only", agenttest.Options{}, ResultVerified, SigSSH},
		{"both valid prefers sigstore", agenttest.Options{Sigstore: goodSigstore()}, ResultVerified, SigSigstore},
		{"sigstore only valid", agenttest.Options{OtherKey: true, Sigstore: goodSigstore()}, ResultVerified, SigSigstore},
		{"bad sigstore, valid ssh", agenttest.Options{Sigstore: &sigstoretest.Options{Repo: "Evil/infra"}}, ResultVerified, SigSSH},
		{"garbage sigstore, valid ssh", agenttest.Options{SigstoreRaw: []byte("x")}, ResultVerified, SigSSH},
		{"both bad", agenttest.Options{OtherKey: true, Sigstore: &sigstoretest.Options{Repo: "Evil/infra"}}, ResultRejected, ""},
		{"bad ssh, no sigstore", agenttest.Options{OtherKey: true}, ResultRejected, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := agenttest.NewWorld(t)
			hub := w.StartHub()
			w.Publish(c.opts)
			a := sigAgent(t, w, SigEither, hub)
			o := cycle(t, a)
			if o.Result != c.result {
				t.Fatalf("outcome %+v", o)
			}
			if c.sig != "" {
				if st := mustState(t, w); st.Verified == nil || st.Verified.Signature != c.sig {
					t.Errorf("state %+v", st.Verified)
				}
			}
		})
	}
}

func TestEitherModeRejectionNamesBothSignatures(t *testing.T) {
	w := agenttest.NewWorld(t)
	w.Publish(agenttest.Options{OtherKey: true, Sigstore: &sigstoretest.Options{Repo: "Evil/infra"}})
	a, _ := newAgentURLs(t, w, ModeVerify, []string{agenttest.DeadURL(t)}, []string{testPin})
	a.Cfg.Signature, a.SigstoreRoot = SigEither, w.Sigstore.TrustedMaterial()
	if err := PrepareDir(a.Cfg.StateDir); err != nil {
		t.Fatal(err)
	}
	l, err := bundle.Load(context.Background(), w.MirrorRepo, bundle.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.verifyFiles(context.Background(), l.Files)
	var rj *RejectError
	if !errors.As(err, &rj) || !strings.Contains(rj.Reason, "Sigstore signature") || !strings.Contains(rj.Reason, "ssh-keygen") {
		t.Fatalf("%v", err)
	}
	t.Log(rj.Reason)
}

func TestSigstoreModeRecheckesABundleVerifiedWithSSH(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	p := w.Publish(agenttest.Options{})
	if o := cycle(t, sigAgent(t, w, SigSSH, hub)); o.Result != ResultVerified {
		t.Fatalf("%+v", o)
	}
	// Same commit, same hub: a 304 would keep the ssh-verified bundle for good. Sigstore mode asks again and finds no
	// Sigstore signature.
	o := cycle(t, sigAgent(t, w, SigSigstore, hub))
	if o.Result != ResultRejected {
		t.Fatalf("%+v", o)
	}
	if st := mustState(t, w); st.Verified.Commit != p.Commit || st.Verified.Signature != SigSSH {
		t.Errorf("state %+v", st.Verified)
	}
}

func TestSameBundleSeenAgainWithSigstoreIsRecordedAsSigstore(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	p := w.Publish(agenttest.Options{Sigstore: goodSigstore()})
	// Verified with ssh first (an agent that has not been switched yet), then seen with sigstore in either mode.
	if o := cycle(t, sigAgent(t, w, SigSSH, hub)); o.Result != ResultVerified {
		t.Fatalf("%+v", o)
	}
	o := cycle(t, sigAgent(t, w, SigEither, hub)) // a 304: nothing to learn
	if o.Result != ResultUnchanged {
		t.Fatalf("%+v", o)
	}
	a := sigAgent(t, w, SigSigstore, hub) // asks again: gets the same bundle with its Sigstore signature
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
	w.Publish(agenttest.Options{Sigstore: goodSigstore()})
	a, _ := newAgent(t, w, ModeApply, hub)
	a.Cfg.Signature = SigSigstore
	a.SigstoreRoot = w.Sigstore.TrustedMaterial()
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
	w.Publish(agenttest.Options{OtherKey: true, Sigstore: goodSigstore()})
	var urls, pins = []string{hub.URL}, []string{hub.Pin}
	vals := map[string]string{
		"INFRA_AGENT_TOKEN":     agenttest.Token(t, pins, urls),
		"INFRA_AGENT_HOST":      agenttest.Host,
		"INFRA_AGENT_AGE_KEY":   w.AgeKeyPath,
		"INFRA_AGENT_SIGNERS":   filepath.Join(w.Dir, "no-such-file"),
		"INFRA_AGENT_STATE_DIR": w.StateDir,
	}
	cfg, err := FromValues(vals, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.CheckFiles(); err == nil {
		t.Error("ssh mode accepted a missing allowed_signers")
	}
	for _, mode := range []string{SigEither} {
		vals["INFRA_AGENT_SIGNATURE"] = mode
		if cfg, _ = FromValues(vals, nil); cfg.Signature != mode {
			t.Fatalf("signature %q", cfg.Signature)
		}
		if _, err := cfg.CheckFiles(); err == nil {
			t.Errorf("%s mode accepted a missing allowed_signers", mode)
		}
	}
	vals["INFRA_AGENT_SIGNATURE"] = SigSigstore
	cfg, err = FromValues(vals, nil)
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
	a.SigstoreRoot = w.Sigstore.TrustedMaterial()
	a.Ansible, a.Out = w.Stub, nopWriter{}
	a.InfraLock, a.InfraApplied = filepath.Join(w.Dir, "infra", "lock"), filepath.Join(w.Dir, "infra-applied")
	if o := cycle(t, a); o.Result != ResultVerified {
		t.Fatalf("%+v", o)
	}
	vals["INFRA_AGENT_SIGNATURE"] = "gpg"
	if _, err := FromValues(vals, nil); !isConfigError(err) || !strings.Contains(err.Error(), "ssh, either or sigstore") {
		t.Errorf("bad mode: %v", err)
	}
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

// A hub that has not been updated ignores the request for format 2 and answers with three files: either mode then
// falls back to ssh, sigstore mode rejects the bundle.
func TestOldHubAnswersWithThreeFiles(t *testing.T) {
	w := agenttest.NewWorld(t)
	w.Publish(agenttest.Options{Sigstore: goodSigstore()})
	l, err := bundle.Load(context.Background(), w.MirrorRepo, bundle.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := bundle.Archive(l.Files, timeOf(l), bundle.Format1)
	if err != nil {
		t.Fatal(err)
	}
	url, pin := fakeHub(t, encryptTo(t, w.AgeID, plain))
	for sig, want := range map[string]string{SigEither: ResultVerified, SigSigstore: ResultRejected} {
		a, _ := newAgentURLs(t, w, ModeVerify, []string{url}, []string{pin})
		a.Cfg.Signature = sig
		a.SigstoreRoot = w.Sigstore.TrustedMaterial()
		o := cycle(t, a)
		if o.Result != want {
			t.Errorf("%s: %+v", sig, o)
		}
		os.RemoveAll(w.StateDir)
	}
}

func TestRequestedFormatDependsOnTheMode(t *testing.T) {
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
	for _, sig := range []string{SigSSH, SigEither, SigSigstore} {
		a, _ := newAgentURLs(t, w, ModeVerify, []string{url}, []string{pin})
		a.Cfg.Signature = sig
		cycle(t, a)
	}
	// ssh mode sends exactly the request the first agents sent; the others ask for format 2.
	if got := strings.Join(seen, ","); got != ",2,2" {
		t.Errorf("%s header values %q, want \",2,2\"", FormatHeader, got)
	}
}

func TestOpenBundleSigstoreMember(t *testing.T) {
	w := agenttest.NewWorld(t)
	w.Publish(agenttest.Options{Sigstore: goodSigstore()})
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
	if f, err := open(st, sg, tb, ss); err != nil || !bytes.Equal(f.Sigstore, l.Files.Sigstore) || !bytes.Equal(f.Statement, l.Files.Statement) {
		t.Fatalf("four members: %v", err)
	}
	if f, err := open(st, sg, tb); err != nil || f.Sigstore != nil {
		t.Fatalf("three members: %v", err)
	}
	for name, ms := range map[string][]member{
		"five members":          {st, sg, tb, ss, ss},
		"sigstore before":       {st, sg, ss, tb},
		"wrong fourth name":     {st, sg, tb, {name: "bundle.sigstore", data: ss.data}},
		"fourth is a symlink":   {st, sg, tb, {name: "bundle.sigstore.json", typ: tar.TypeSymlink}},
		"fourth is too large":   {st, sg, tb, {name: "bundle.sigstore.json", data: bytes.Repeat([]byte("x"), bundle.MaxSigstore+1)}},
		"fourth then something": {st, sg, tb, ss, {name: "x", data: []byte("x")}},
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
	for _, sig := range []string{SigSigstore, SigEither} {
		t.Run(sig, func(t *testing.T) {
			w := agenttest.NewWorld(t)
			p := w.Publish(agenttest.Options{OtherKey: true, Sigstore: goodSigstore()})
			a := githubAgent(t, w, ModeVerify, w.MirrorRepo, agenttest.DeadURL(t))
			a.Cfg.Signature = sig
			a.SigstoreRoot = w.Sigstore.TrustedMaterial()
			o := cycle(t, a)
			if o.Result != ResultVerified || o.Hub != GitHubSource {
				t.Fatalf("outcome %+v", o)
			}
			if st := mustState(t, w); st.Verified.Commit != p.Commit || st.Verified.Signature != SigSigstore {
				t.Errorf("state %+v", st.Verified)
			}
		})
	}
	// Without the file in the tree, sigstore mode rejects what GitHub holds.
	w := agenttest.NewWorld(t)
	w.Publish(agenttest.Options{})
	a := githubAgent(t, w, ModeVerify, w.MirrorRepo, agenttest.DeadURL(t))
	a.Cfg.Signature = SigSigstore
	a.SigstoreRoot = w.Sigstore.TrustedMaterial()
	if o := cycle(t, a); o.Result != ResultRejected || o.Hub != GitHubSource || !strings.Contains(o.Message, "bundle.sigstore.json") {
		t.Fatalf("outcome %+v", o)
	}
}

func TestEmbeddedRootIsUsedWhenNothingIsInjected(t *testing.T) {
	w := agenttest.NewWorld(t)
	w.Publish(agenttest.Options{Sigstore: goodSigstore()}) // signed by a throwaway Sigstore: the public-good root rejects it
	a, _ := newAgentURLs(t, w, ModeVerify, []string{agenttest.DeadURL(t)}, []string{testPin})
	a.Cfg.Signature = SigSigstore
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
