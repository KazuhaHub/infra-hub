package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/KazuhaHub/infra-hub/internal/agenttest"
	"github.com/KazuhaHub/infra-hub/internal/testutil"
)

// githubAgent is an agent whose hubs are all down (or the given ones) and whose GitHub repository is the world's
// main-attestation repository, read as a filesystem path (git fetches from a path the same way as from a URL).
func githubAgent(t *testing.T, w *agenttest.World, mode, repo string, hubs ...string) *Agent {
	t.Helper()
	fileRepos(t)
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
	fileRepos(t)
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
	fileRepos(t)
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
	fileRepos(t)
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
	fileRepos(t)
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

func TestGitHubNewerBundleAfterVerified(t *testing.T) {
	fileRepos(t)
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	p1 := w.Publish(agenttest.Options{})
	a, _ := newAgent(t, w, ModeApply, hub)
	if o := cycle(t, a); o.Result != ResultOK {
		t.Fatalf("first cycle %+v", o)
	}
	hub.Stop()
	p2 := w.Publish(agenttest.Options{Time: p1.Time + 100})
	a.Cfg.GitHubRepo = w.MirrorRepo
	o := cycle(t, a)
	if o.Result != ResultOK || o.Hub != GitHubSource || o.AppliedCommit != p2.Commit || len(w.StubRuns()) != 2 {
		t.Fatalf("outcome %+v, runs %v", o, w.StubRuns())
	}
}

func TestGitHubSecondFetchAndRecovery(t *testing.T) {
	w := agenttest.NewWorld(t)
	p1 := w.Publish(agenttest.Options{})
	a := githubAgent(t, w, ModeApply, w.MirrorRepo, agenttest.DeadURL(t))
	if o := cycle(t, a); o.Result != ResultOK || o.AppliedCommit != p1.Commit {
		t.Fatalf("first %+v", o)
	}
	// A newer tip is fetched into the existing shallow repository.
	p2 := w.Publish(agenttest.Options{Time: p1.Time + 100})
	if o := cycle(t, a); o.Result != ResultOK || o.AppliedCommit != p2.Commit {
		t.Fatalf("second %+v", o)
	}
	// A killed git leaves a lock and a damaged object behind: the next fallback starts over and succeeds.
	gd := githubDir(w.StateDir)
	if err := os.WriteFile(filepath.Join(gd, "shallow.lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(gd, "objects", "ab"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gd, "objects", "ab", "cdef0123456789abcdef0123456789abcdef01"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	p3 := w.Publish(agenttest.Options{Time: p1.Time + 200})
	if o := cycle(t, a); o.Result != ResultOK || o.AppliedCommit != p3.Commit {
		t.Fatalf("after damage %+v", o)
	}
	if _, err := os.Stat(filepath.Join(gd, "shallow.lock")); err == nil {
		t.Errorf("the lock is still there")
	}
}

func TestGitHubMalformedTreeIsRejected(t *testing.T) {
	fileRepos(t)
	w := agenttest.NewWorld(t)
	w.Publish(agenttest.Options{})
	// A tree whose tarball is gone: the fetch works, the bundle is not there.
	testutil.RunGit(t, filepath.Dir(w.MirrorRepo), "rm", "-q", "bundle.tar.gz")
	testutil.RunGit(t, filepath.Dir(w.MirrorRepo), "commit", "-q", "-m", "drop the tarball")
	a := githubAgent(t, w, ModeApply, w.MirrorRepo, agenttest.DeadURL(t))
	o := cycle(t, a)
	if o.Result != ResultRejected || o.Hub != GitHubSource || !strings.Contains(o.Message, "GitHub") {
		t.Fatalf("outcome %+v", o)
	}
}

func TestGitHubLegacyFloor(t *testing.T) {
	w := agenttest.NewWorld(t)
	p := w.Publish(agenttest.Options{})
	a := githubAgent(t, w, ModeVerify, w.MirrorRepo, agenttest.DeadURL(t))
	floor := func(at int64) {
		line := strings.Repeat("a", 40) + " " + strconv.FormatInt(at, 10) + "\n"
		if err := os.WriteFile(a.InfraApplied, []byte(line), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	floor(p.Time + 1000) // infra-pull applied a main that is newer than this bundle
	if o := cycle(t, a); o.Result != ResultUnchanged || len(releases(t, w)) != 0 {
		t.Fatalf("older than the floor: %+v", o)
	}
	floor(p.Time) // a bundle signed at the applied time is that main or newer
	if o := cycle(t, a); o.Result != ResultVerified {
		t.Fatalf("at the floor: %+v", o)
	}
}

func TestGitHubCorruptBlobAtUnchangedTip(t *testing.T) {
	w := agenttest.NewWorld(t)
	p := w.Publish(agenttest.Options{})
	a := githubAgent(t, w, ModeApply, w.MirrorRepo, agenttest.DeadURL(t))
	if o := cycle(t, a); o.Result != ResultOK || o.AppliedCommit != p.Commit {
		t.Fatalf("first %+v", o)
	}
	gd := githubDir(w.StateDir)
	out, err := exec.Command("git", "--git-dir", gd, "rev-parse", "main-attestation:bundle.tar.gz").Output()
	if err != nil {
		t.Fatal(err)
	}
	id := strings.TrimSpace(string(out))
	obj := filepath.Join(gd, "objects", id[:2], id[2:])
	if err := os.Chmod(obj, 0o644); err != nil {
		t.Fatalf("the blob is not a loose object: %v", err)
	}
	if err := os.WriteFile(obj, []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The tip is unchanged, so the fetch has nothing to do and reading the blob fails: the repository is rebuilt.
	o := cycle(t, a)
	if o.Result != ResultUnchanged || o.Hub != GitHubSource {
		t.Fatalf("after corruption %+v", o)
	}
	if err := exec.Command("git", "--git-dir", gd, "cat-file", "-p", id).Run(); err != nil {
		t.Errorf("the blob is still damaged: %v", err)
	}
}
