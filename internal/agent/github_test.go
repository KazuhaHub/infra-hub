package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KazuhaHub/infra-hub/internal/agenttest"
)

// githubAgent is an agent whose hubs are all down (or the given ones) and whose GitHub repository is the world's
// main-attestation repository, read as a filesystem path (git fetches from a path the same way as from a URL).
func githubAgent(t *testing.T, w *agenttest.World, mode, repo string, hubs ...string) *Agent {
	t.Helper()
	a, _ := newAgentURLs(t, w, mode, hubs, []string{testPin})
	a.Cfg.GitHubRepo = repo
	return a
}

func githubCloned(w *agenttest.World) bool {
	_, err := os.Stat(filepath.Join(w.StateDir, "github.git"))
	return err == nil
}

func TestGitHubFallbackWhenAllHubsAreDown(t *testing.T) {
	for _, mode := range []string{ModeApply, ModeVerify} {
		t.Run(mode, func(t *testing.T) {
			w := agenttest.NewWorld(t)
			p := w.Publish(agenttest.Options{})
			a := githubAgent(t, w, mode, w.MirrorRepo, agenttest.DeadURL(t), agenttest.DeadURL(t))
			o := cycle(t, a)
			wantResult := ResultOK
			if mode == ModeVerify {
				wantResult = ResultVerified
			}
			if o.Result != wantResult || o.Hub != GitHubSource || !strings.Contains(o.Message, "from GitHub, no hub gave a bundle") {
				t.Fatalf("outcome %+v", o)
			}
			st := mustState(t, w)
			if st.Verified == nil || st.Verified.Commit != p.Commit || st.LastHub != GitHubSource {
				t.Errorf("state %+v", st)
			}
			if mode == ModeApply {
				if st.Applied == nil || st.Applied.Commit != p.Commit || len(w.StubRuns()) != 1 {
					t.Errorf("state %+v, runs %v", st, w.StubRuns())
				}
			} else if len(w.StubRuns()) != 0 {
				t.Errorf("verify mode applied: %v", w.StubRuns())
			}
			if _, err := os.Stat(ReleaseDir(w.StateDir, p.Commit)); err != nil {
				t.Errorf("not extracted: %v", err)
			}
			// The next cycle fetches again, finds the same bundle and has nothing new.
			if o := cycle(t, a); o.Result != ResultUnchanged || o.Hub != GitHubSource {
				t.Errorf("second cycle %+v", o)
			}
		})
	}
}

func TestGitHubIsNotAskedWhileAHubServes(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	w.Publish(agenttest.Options{})
	missing := filepath.Join(w.Dir, "no-such-repo")
	a, _ := newAgent(t, w, ModeApply, hub)
	a.Cfg.GitHubRepo = missing
	o := cycle(t, a)
	if o.Result != ResultOK || o.Hub != hub.URL || strings.Contains(o.Message, "GitHub") || githubCloned(w) {
		t.Fatalf("outcome %+v", o)
	}
	// Nothing new (304) is an answer too: no GitHub.
	o = cycle(t, a)
	if o.Result != ResultUnchanged || o.Hub != hub.URL || strings.Contains(o.Message, "GitHub") || githubCloned(w) {
		t.Fatalf("second cycle %+v", o)
	}
	// An older bundle behind a healthy hub is "nothing new" as well.
	w.Publish(agenttest.Options{Time: 1000})
	o = cycle(t, a)
	if o.Result != ResultUnchanged || strings.Contains(o.Message, "GitHub") || githubCloned(w) {
		t.Fatalf("older bundle %+v", o)
	}
}

func TestGitHubBundleIsChecked(t *testing.T) {
	cases := map[string]agenttest.Options{
		"wrong signature key": {OtherKey: true},
		"hash mismatch":       {WrongHash: true},
		"wrong repo":          {Repo: "Evil/infra"},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			w := agenttest.NewWorld(t)
			w.Publish(opts)
			a := githubAgent(t, w, ModeApply, w.MirrorRepo, agenttest.DeadURL(t))
			o := cycle(t, a)
			if o.Result != ResultRejected || o.Hub != GitHubSource || !strings.Contains(o.Message, "GitHub") {
				t.Fatalf("outcome %+v", o)
			}
			if got := releases(t, w); len(got) != 0 || len(w.StubRuns()) != 0 {
				t.Errorf("extracted %v, applied %v", got, w.StubRuns())
			}
			if st := mustState(t, w); st.Verified != nil || st.Applied != nil {
				t.Errorf("state %+v", st)
			}
		})
	}
}

func TestGitHubOlderBundleIsIgnored(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	p1 := w.Publish(agenttest.Options{})
	a, _ := newAgent(t, w, ModeApply, hub)
	if o := cycle(t, a); o.Result != ResultOK {
		t.Fatalf("first cycle %+v", o)
	}
	hub.Stop()
	p2 := w.Publish(agenttest.Options{Time: p1.Time - 500})
	a.Cfg.GitHubRepo = w.MirrorRepo
	o := cycle(t, a)
	if o.Result != ResultUnchanged || o.Hub != GitHubSource || len(w.StubRuns()) != 1 {
		t.Fatalf("outcome %+v, runs %v", o, w.StubRuns())
	}
	for _, r := range releases(t, w) {
		if r == p2.Commit {
			t.Errorf("the older bundle was extracted")
		}
	}
	if st := mustState(t, w); st.Verified.Commit != p1.Commit || st.Applied.Commit != p1.Commit {
		t.Errorf("state moved back: %+v", st)
	}
}

func TestGitHubFallbackOff(t *testing.T) {
	w := agenttest.NewWorld(t)
	w.Publish(agenttest.Options{})
	a := githubAgent(t, w, ModeApply, "", agenttest.DeadURL(t))
	o := cycle(t, a)
	if o.Result != ResultUnreachable || strings.Contains(o.Message, "GitHub") || githubCloned(w) || len(w.StubRuns()) != 0 {
		t.Fatalf("outcome %+v", o)
	}
}

func TestGitHubFetchFailureIsAppended(t *testing.T) {
	w := agenttest.NewWorld(t)
	w.Publish(agenttest.Options{})
	missing := filepath.Join(w.Dir, "no-such-repo")
	a := githubAgent(t, w, ModeApply, missing, agenttest.DeadURL(t))
	o := cycle(t, a)
	if o.Result != ResultUnreachable || !strings.Contains(o.Message, "no hub gave a bundle (1 of 1 tried); GitHub fallback: ") {
		t.Fatalf("unreachable: %+v", o)
	}

	// All hubs rejecting is kept as rejected, with the failure appended.
	w2 := agenttest.NewWorld(t)
	hub := w2.StartHub()
	w2.Publish(agenttest.Options{OtherKey: true})
	b, _ := newAgent(t, w2, ModeApply, hub)
	b.Cfg.GitHubRepo = filepath.Join(w2.Dir, "no-such-repo")
	o = cycle(t, b)
	if o.Result != ResultRejected || o.Hub != hub.URL || !strings.Contains(o.Message, "; GitHub fallback: ") {
		t.Fatalf("rejected: %+v", o)
	}
}

func TestGitHubRejectionKeepsTheHubNotes(t *testing.T) {
	// The hub serves a bundle that fails the signature check, and so does GitHub.
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	w.Publish(agenttest.Options{OtherKey: true})
	a, _ := newAgent(t, w, ModeVerify, hub)
	a.Cfg.GitHubRepo = w.MirrorRepo // the same bad bundle: still rejected, now as the GitHub one
	o := cycle(t, a)
	if o.Result != ResultRejected || o.Hub != GitHubSource || !strings.Contains(o.Message, hub.URL) {
		t.Fatalf("outcome %+v", o)
	}
}
