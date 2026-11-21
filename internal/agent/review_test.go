package agent

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/agenttest"
	"github.com/KazuhaHub/infra-hub/internal/bundle"
	"github.com/KazuhaHub/infra-hub/internal/hubtrust"
)

func TestReplayOfTheAppliedBundleAfterAFailedApplyIsNotReapplied(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	p1 := w.Publish(agenttest.Options{})
	a, clk := newAgent(t, w, ModeApply, hub)
	if o := cycle(t, a); o.Result != ResultOK {
		t.Fatalf("%+v", o)
	}
	w.FailStub(true)
	p2 := w.Publish(agenttest.Options{})
	if o := cycle(t, a); o.Result != ResultFailed {
		t.Fatalf("%+v", o)
	}
	// The hub (or whoever sits before it) now replays the first bundle, which the agent has applied, and the 24 h rule is
	// due as well: the old bundle must be ignored, and the retry applies the newer one that is already verified.
	w.Republish(p1.Commit)
	w.FailStub(false)
	clk.t = clk.t.Add(25 * time.Hour)
	o := cycle(t, a)
	if o.Result != ResultOK || o.AppliedCommit != p2.Commit {
		t.Fatalf("outcome %+v", o)
	}
	runs := w.StubRuns()
	if last := runs[len(runs)-1]; !strings.Contains(last, p2.Commit) || strings.Contains(last, p1.Commit) {
		t.Errorf("ansible ran for %q", last)
	}
	st := mustState(t, w)
	if st.Applied.Commit != p2.Commit || st.Applied.Time.Unix() != p2.Time || st.Verified.Commit != p2.Commit {
		t.Errorf("state %+v / %+v", st.Applied, st.Verified)
	}
	// And a replay when nothing is pending, with the 24 h rule due, re-applies the newest, never the replayed one.
	clk.t = clk.t.Add(25 * time.Hour)
	if o := cycle(t, a); o.Result != ResultOK || o.AppliedCommit != p2.Commit {
		t.Fatalf("%+v", o)
	}
	if runs := w.StubRuns(); strings.Contains(runs[len(runs)-1], p1.Commit) {
		t.Errorf("the replayed bundle was applied")
	}
}

func TestApplyWaitsForInfraPullsLock(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	p := w.Publish(agenttest.Options{})
	a, _ := newAgent(t, w, ModeApply, hub)
	held, err := LockFile(context.Background(), a.InfraLock, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	o := cycle(t, a)
	if o.Result != ResultFailed || o.Message != "another run holds "+a.InfraLock || len(w.StubRuns()) != 0 {
		t.Fatalf("outcome %+v", o)
	}
	if st := mustState(t, w); st.Applied != nil {
		t.Errorf("state moved: %+v", st.Applied)
	}
	// Released while the agent waits: it gets the lock and applies.
	a.LockTimeout = 5 * time.Second
	go func() { time.Sleep(400 * time.Millisecond); held.Close() }()
	if o := cycle(t, a); o.Result != ResultOK || o.AppliedCommit != p.Commit {
		t.Fatalf("after release: %+v", o)
	}
	// The agent let go of it again afterwards.
	f, err := LockFile(context.Background(), a.InfraLock, 0)
	if err != nil {
		t.Fatalf("the agent kept the lock: %v", err)
	}
	f.Close()
	// Verify mode never touches it.
	held, _ = LockFile(context.Background(), a.InfraLock, time.Second)
	defer held.Close()
	a.Cfg.Mode = ModeVerify
	if o := cycle(t, a); o.Result == ResultFailed {
		t.Errorf("verify mode waited for the lock: %+v", o)
	}
}

func TestInitialFloorFromInfraPull(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	a, _ := newAgent(t, w, ModeVerify, hub)
	floor := int64(1790000000 + 250)
	os.WriteFile(a.InfraApplied, []byte(fmt.Sprintf("%040x %d\n", 7, floor)), 0o644)

	old := w.Publish(agenttest.Options{Time: floor - 1})
	o := cycle(t, a)
	if o.Result != ResultUnchanged || len(releases(t, w)) != 0 || mustState(t, w).Verified != nil {
		t.Fatalf("a bundle signed before infra-pull's apply: %+v", o)
	}
	_ = old
	fresh := w.Publish(agenttest.Options{Time: floor})
	if o := cycle(t, a); o.Result != ResultVerified {
		t.Fatalf("a bundle signed at the floor: %+v", o)
	}
	// Once the state has a mark, the file is not consulted (a broken one does not matter) and the mark decides.
	_ = fresh
	os.WriteFile(a.InfraApplied, []byte("garbage"), 0o644)
	w.Publish(agenttest.Options{Time: floor + 10})
	if o := cycle(t, a); o.Result != ResultVerified {
		t.Fatalf("%+v", o)
	}
	w.Publish(agenttest.Options{Time: floor + 5})
	if o := cycle(t, a); o.Result != ResultUnchanged {
		t.Fatalf("%+v", o)
	}
}

func TestInfraPullRecordMalformedIsAFailedCycleAndZeroMeansWait(t *testing.T) {
	for name, content := range map[string]string{"one field": "abc\n", "short commit": "abc 1790000000\n", "no time": strings.Repeat("a", 40) + " soon\n",
		"negative": strings.Repeat("a", 40) + " -5\n", "three fields": strings.Repeat("a", 40) + " 1 2\n", "empty": ""} {
		t.Run(name, func(t *testing.T) {
			w := agenttest.NewWorld(t)
			hub := w.StartHub()
			w.Publish(agenttest.Options{})
			a, _ := newAgent(t, w, ModeVerify, hub)
			os.WriteFile(a.InfraApplied, []byte(content), 0o644)
			o := cycle(t, a) // no error: the daemon must not crash-loop
			if o.Result != ResultFailed || !strings.Contains(o.Message, a.InfraApplied) || !strings.Contains(o.Message, "malformed") {
				t.Fatalf("outcome %+v", o)
			}
			if len(releases(t, w)) != 0 || mustState(t, w).Verified != nil {
				t.Errorf("something was verified")
			}
			if rep, ok := hub.Report(t); !ok || rep.Result != "failed" {
				t.Errorf("hub report %+v", rep)
			}
		})
	}
	// infra-pull writes "<commit> 0" when it seeds its floor: valid, the floor is unknown, nothing is verified, and it
	// is not an error. Once infra-pull records a time the agent goes on.
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	w.Publish(agenttest.Options{Time: 1790000100})
	a, _ := newAgent(t, w, ModeVerify, hub)
	os.WriteFile(a.InfraApplied, []byte(strings.Repeat("a", 40)+" 0\n"), 0o644)
	o := cycle(t, a)
	if o.Result != ResultUnchanged || o.Message != "waiting for infra-pull to record an applied time" || len(releases(t, w)) != 0 {
		t.Fatalf("outcome %+v", o)
	}
	os.WriteFile(a.InfraApplied, []byte(strings.Repeat("a", 40)+" 1790000000\n"), 0o644)
	if o := cycle(t, a); o.Result != ResultVerified {
		t.Fatalf("after infra-pull recorded a time: %+v", o)
	}
	if n, err := a.LegacyFloor(); n != 1790000000 || err != nil {
		t.Errorf("%d %v", n, err)
	}
	w2 := agenttest.NewWorld(t)
	a2, _ := newAgent(t, w2, ModeVerify, w2.StartHub())
	if n, err := a2.LegacyFloor(); n != 0 || err != nil { // a missing file is no floor
		t.Errorf("missing file: %d %v", n, err)
	}
}

// fakeHubFunc is a TLS server with its own handler; it returns the URL and pin.
func fakeHubFunc(t *testing.T, h http.HandlerFunc) (string, string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	cert, err := x509.ParseCertificate(srv.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return srv.URL, hubtrust.Pin(cert)
}

// bundleBody is the encrypted archive of the bundle currently published in w's mirror.
func bundleBody(t *testing.T, w *agenttest.World) []byte {
	t.Helper()
	l, err := bundle.Load(context.Background(), w.MirrorRepo, bundle.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := bundle.Archive(l.Files, time.Unix(l.Statement.Time, 0), bundle.Format1)
	if err != nil {
		t.Fatal(err)
	}
	return encryptTo(t, w.AgeID, plain)
}

func TestAnOlderBundleFromOneHubDoesNotStopTheSearch(t *testing.T) {
	w := agenttest.NewWorld(t)
	live := w.StartHub()
	w.Publish(agenttest.Options{})
	url, pin := fakeHub(t, bundleBody(t, w)) // the first bundle, which stays on this hub
	w.Publish(agenttest.Options{})
	a, _ := newAgentURLs(t, w, ModeVerify, []string{live.URL}, []string{live.Pin})
	if o := cycle(t, a); o.Result != ResultVerified {
		t.Fatalf("%+v", o)
	}
	p3 := w.Publish(agenttest.Options{})
	// The first hub serves the older bundle (the one already verified, with another time would do as well); the second
	// has the newest.
	a, _ = newAgentURLs(t, w, ModeVerify, []string{url, live.URL}, []string{pin, live.Pin})
	o := cycle(t, a)
	if o.Result != ResultVerified || o.Hub != live.URL || mustState(t, w).Verified.Commit != p3.Commit {
		t.Fatalf("%+v, state %+v", o, mustState(t, w).Verified)
	}
	// With nobody ahead, the hub with the older bundle is the one that served, and the result is unchanged.
	a, _ = newAgentURLs(t, w, ModeVerify, []string{url}, []string{pin})
	if o := cycle(t, a); o.Result != ResultUnchanged || o.Hub != url {
		t.Fatalf("%+v", o)
	}
	if st := mustState(t, w); st.Verified.Commit != p3.Commit {
		t.Errorf("moved back: %+v", st.Verified)
	}
}

func TestUnbelievable304IsAHubError(t *testing.T) {
	w := agenttest.NewWorld(t)
	live := w.StartHub()
	p := w.Publish(agenttest.Options{})
	for name, etag := range map[string]string{"no ETag": "", "other ETag": `"` + strings.Repeat("0", 40) + `"`} {
		t.Run(name, func(t *testing.T) {
			url, pin := fakeHubFunc(t, func(rw http.ResponseWriter, r *http.Request) {
				if etag != "" {
					rw.Header().Set("ETag", etag)
				}
				rw.WriteHeader(http.StatusNotModified)
			})
			h, _ := NewHub(url, []string{pin})
			if _, err := h.Bundle(context.Background(), agenttest.Host, p.Commit, 1, func(io.Reader) error { return nil }); err == nil {
				t.Error("accepted")
			}
		})
	}
	// Without If-None-Match even a well formed 304 is wrong; the cycle moves on to the next hub.
	url, pin := fakeHubFunc(t, func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("ETag", `"`+p.Commit+`"`)
		rw.WriteHeader(http.StatusNotModified)
	})
	a, _ := newAgentURLs(t, w, ModeVerify, []string{url, live.URL}, []string{pin, live.Pin})
	o := cycle(t, a)
	if o.Result != ResultVerified || o.Hub != live.URL {
		t.Fatalf("%+v", o)
	}
}

func TestRejectedBundleIsReportedEvenWhenAnotherHubSucceeds(t *testing.T) {
	w := agenttest.NewWorld(t)
	live := w.StartHub()
	w.Publish(agenttest.Options{})
	var challenges atomic.Int32
	bad, badPin := fakeHubFunc(t, func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/bundle/"):
			rw.Write([]byte("this is not an age file"))
		case r.URL.Path == "/v1/challenge":
			challenges.Add(1)
			http.Error(rw, "no", 500)
		}
	})
	a, _ := newAgentURLs(t, w, ModeVerify, []string{bad, live.URL}, []string{badPin, live.Pin})
	o := cycle(t, a)
	want := "hub " + bad + " served a rejected bundle: "
	if o.Result != ResultVerified || o.Hub != live.URL || !strings.Contains(o.Message, want) {
		t.Fatalf("%+v", o)
	}
	if challenges.Load() == 0 {
		t.Error("the rejecting hub did not get the report")
	}
	if rep, ok := live.Report(t); !ok || !strings.Contains(rep.Message, want) || rep.Result != "verified" {
		t.Errorf("hub report %+v", rep)
	} else if len(rep.RejectedHubs) != 1 || rep.RejectedHubs[0] != bad {
		t.Errorf("rejectedHubs %v, want [%s]", rep.RejectedHubs, bad)
	}
}

func TestReportGoesToEveryHubWhenTheFirstDidNotServe(t *testing.T) {
	w := agenttest.NewWorld(t)
	first := w.StartHubEmpty()
	live := w.StartHub()
	w.Publish(agenttest.Options{})
	a, _ := newAgent(t, w, ModeVerify, first, live)
	if o := cycle(t, a); o.Result != ResultVerified || o.Hub != live.URL {
		t.Fatalf("%+v", o)
	}
	for name, h := range map[string]*agenttest.Hub{"first": first, "serving": live} {
		if rep, ok := h.Report(t); !ok || rep.Result != "verified" {
			t.Errorf("%s hub report %+v", name, rep)
		}
	}
	// When the first hub serves, the others are only a fallback.
	second := w.StartHubEmpty()
	a, _ = newAgent(t, w, ModeVerify, live, second)
	cycle(t, a)
	if _, ok := second.Report(t); ok {
		t.Errorf("the second hub got a report although the first delivered it")
	}
}

func TestResponseIsStreamedAndCapped(t *testing.T) {
	w := agenttest.NewWorld(t)
	w.Publish(agenttest.Options{})
	good := bundleBody(t, w)
	old := responseLimit
	defer func() { responseLimit = old }()

	// A response over the limit is a hub fault (try the next hub, result unreachable), not a rejected bundle.
	responseLimit = int64(len(good) - 1)
	url, pin := fakeHub(t, good)
	a, _ := newAgentURLs(t, w, ModeVerify, []string{url}, []string{pin})
	if o := cycle(t, a); o.Result != ResultUnreachable {
		t.Fatalf("over the cap: %+v", o)
	}
	responseLimit = old

	// A connection that breaks in the middle of the body is a network error as well.
	cut, cutPin := fakeHubFunc(t, func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Length", fmt.Sprint(len(good)))
		rw.Write(good[:len(good)/2])
		panic(http.ErrAbortHandler)
	})
	a, _ = newAgentURLs(t, w, ModeVerify, []string{cut}, []string{cutPin})
	if o := cycle(t, a); o.Result != ResultUnreachable {
		t.Fatalf("broken connection: %+v", o)
	}
	// Whole, it passes.
	a, _ = newAgentURLs(t, w, ModeVerify, []string{url}, []string{pin})
	if o := cycle(t, a); o.Result != ResultVerified {
		t.Fatalf("intact: %+v", o)
	}
}

func TestStateDirIsNeverChmodded(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "state")
	if err := PrepareDir(dir); err != nil { // created
		t.Fatal(err)
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Errorf("created with %v", st.Mode())
	}
	if err := PrepareDir(dir); err != nil { // fine as it is
		t.Fatal(err)
	}
	os.Chmod(dir, 0o755)
	err := PrepareDir(dir)
	if !isConfigError(err) || !strings.Contains(err.Error(), "0755") {
		t.Fatalf("err %v", err)
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o755 {
		t.Errorf("the mode was changed to %v", st.Mode())
	}
	file := filepath.Join(base, "file")
	os.WriteFile(file, nil, 0o600)
	if err := PrepareDir(file); !isConfigError(err) {
		t.Errorf("a file: %v", err)
	}
	link := filepath.Join(base, "link")
	os.Symlink(base, link)
	if err := PrepareDir(link); !isConfigError(err) {
		t.Errorf("a symlink: %v", err)
	}
	// The cycle refuses too, and does not run.
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	w.Publish(agenttest.Options{})
	a, _ := newAgent(t, w, ModeVerify, hub)
	os.MkdirAll(w.StateDir, 0o755)
	os.Chmod(w.StateDir, 0o750)
	if _, err := a.Cycle(context.Background()); !isConfigError(err) {
		t.Errorf("cycle: %v", err)
	}
}

func TestContentConflictsAreRejectedAndLocalFaultsAreNot(t *testing.T) {
	for name, es := range map[string][]tent{
		"file then directory": {{name: "infra/a", data: "x"}, {name: "infra/a/", typ: tar.TypeDir}},
		"file as a parent":    {{name: "infra/a", data: "x"}, {name: "infra/a/b/c", data: "y"}},
		"directory then file": {{name: "infra/a/", typ: tar.TypeDir}, {name: "infra/a", data: "x"}},
		"symlink over file":   {{name: "infra/a", data: "x"}, {name: "infra/a", typ: tar.TypeSymlink, link: "b"}},
		"link over file":      {{name: "infra/a", data: "x"}, {name: "infra/b", data: "y"}, {name: "infra/a", typ: tar.TypeLink, link: "infra/b"}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := extractInto(t, es...)
			if _, ok := err.(*RejectError); !ok {
				t.Errorf("error %T %v, want a RejectError", err, err)
			}
		})
	}
	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere")
	}
	dst := filepath.Join(t.TempDir(), "ro")
	os.Mkdir(dst, 0o500)
	err := ExtractTar(dst, bytes.NewReader(gz(t, tarEntries(t, tent{name: "infra/x", data: "x"}))))
	if err == nil {
		t.Fatal("wrote into a read-only directory")
	}
	if _, ok := err.(*RejectError); ok {
		t.Errorf("a local permission fault was blamed on the bundle: %v", err)
	}
}

func TestSignatureToolFailuresAreClassified(t *testing.T) {
	dir := t.TempDir()
	script := func(name, body string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755)
		return p
	}
	// A verification failure is a rejection; a tool that hangs or cannot run is a local fault.
	if err := VerifySignature(context.Background(), script("no", "exit 255"), "/x", dir, []byte("s"), []byte("g")); !isReject(err) {
		t.Errorf("exit 255: %v", err)
	}
	old := verifyTimeout
	verifyTimeout = 200 * time.Millisecond
	defer func() { verifyTimeout = old }()
	err := VerifySignature(context.Background(), script("slow", "exec sleep 5"), "/x", dir, []byte("s"), []byte("g"))
	if err == nil || isReject(err) {
		t.Errorf("timeout: %v", err)
	}
	if err := VerifySignature(context.Background(), filepath.Join(dir, "missing"), "/x", dir, []byte("s"), []byte("g")); err == nil || isReject(err) {
		t.Errorf("missing tool: %v", err)
	}
	// In a cycle the timeout is result failed, and nothing is extracted.
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	w.Publish(agenttest.Options{})
	a, _ := newAgent(t, w, ModeApply, hub)
	a.SSHKeygen = script("slow2", "exec sleep 5")
	if o := cycle(t, a); o.Result != ResultFailed || len(releases(t, w)) != 0 {
		t.Errorf("%+v", o)
	}
}

func isReject(err error) bool { _, ok := err.(*RejectError); return ok }

func TestApplyKillsTheWholeProcessGroup(t *testing.T) {
	dir := t.TempDir()
	rel := filepath.Join(dir, "rel")
	os.MkdirAll(filepath.Join(rel, "infra"), 0o755)
	pidFile := filepath.Join(dir, "child.pid")
	// The script and its child both ignore SIGTERM (ignored signals are inherited), so only SIGKILL to the group ends them.
	stub := filepath.Join(dir, "ansible-playbook")
	os.WriteFile(stub, []byte("#!/bin/sh\ntrap '' TERM\nsleep 300 &\necho $! > "+pidFile+"\nwait\n"), 0o755)
	old := killGrace
	killGrace = 300 * time.Millisecond
	defer func() { killGrace = old }()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := Apply(ctx, stub, rel, "web1", "/age", "/restart", io.Discard)
	if err == nil || !strings.Contains(err.Error(), "stopped") {
		t.Fatalf("err %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("took %s", time.Since(start))
	}
	raw, _ := os.ReadFile(pidFile)
	var pid int
	fmt.Sscan(string(raw), &pid)
	if pid == 0 {
		t.Fatal("the child never started")
	}
	deadline := time.Now().Add(3 * time.Second)
	for syscall.Kill(pid, 0) == nil && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		// a zombie is reaped by init; wait until it is gone
	}
	if syscall.Kill(pid, 0) == nil {
		t.Errorf("the child %d survived", pid)
	}
}

func TestInterruptedCycleKeepsTheLastResult(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	w.Publish(agenttest.Options{})
	a, _ := newAgent(t, w, ModeApply, hub)
	if o := cycle(t, a); o.Result != ResultOK {
		t.Fatalf("%+v", o)
	}
	before := mustState(t, w)
	p2 := w.Publish(agenttest.Options{})
	slow := filepath.Join(w.Dir, "slow-ansible")
	os.WriteFile(slow, []byte("#!/bin/sh\nexec sleep 30\n"), 0o755)
	a.Ansible = slow
	old := killGrace
	killGrace = 200 * time.Millisecond
	defer func() { killGrace = old }()
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	_, err := a.Cycle(ctx)
	if err == nil || !strings.Contains(err.Error(), "interrupted") {
		t.Fatalf("err %v", err)
	}
	after := mustState(t, w)
	if after.LastResult != before.LastResult || after.LastMessage != before.LastMessage || !after.LastCycle.Equal(*before.LastCycle) {
		t.Errorf("the interrupted cycle changed the last result: %+v -> %+v", before, after)
	}
	if after.Applied.Commit != before.Applied.Commit || after.Verified.Commit != p2.Commit {
		t.Errorf("state %+v / %+v", after.Applied, after.Verified)
	}
}

func TestLoopStopsOnCancel(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	w.Publish(agenttest.Options{})
	a, _ := newAgent(t, w, ModeVerify, hub)

	// Cancelled during the initial delay: it returns at once and no cycle ran.
	a.Cfg.Interval = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Loop(ctx); close(done) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Loop did not stop")
	}

	// Running: several cycles at a short interval, then a prompt stop.
	a.Cfg.Interval = 100 * time.Millisecond
	ctx, cancel = context.WithCancel(context.Background())
	done = make(chan struct{})
	go func() { a.Loop(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := LoadState(w.StateDir); err == nil && st.LastResult == ResultUnchanged {
			break // the second cycle (the first verified, the next found nothing new) has run
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Loop did not stop")
	}
	if st := mustState(t, w); st.LastResult != ResultUnchanged {
		t.Errorf("state %+v", st)
	}
}

func TestJitterBounds(t *testing.T) {
	d := 5 * time.Minute
	lo, hi := d, d
	for i := 0; i < 20000; i++ {
		j := Jitter(d)
		lo, hi = min(lo, j), max(hi, j)
		if j < d-d/10 || j > d+d/10 {
			t.Fatalf("Jitter(%s) = %s is outside ±10%%", d, j)
		}
	}
	if lo > d-d/12 || hi < d+d/12 {
		t.Errorf("no spread: %s .. %s", lo, hi)
	}
}

func TestAHubWithNothingNewDoesNotEndTheSearch(t *testing.T) {
	w := agenttest.NewWorld(t)
	live := w.StartHub()
	w.Publish(agenttest.Options{})
	same, samePin := fakeHub(t, bundleBody(t, w)) // stays on the first bundle
	notMod, notModPin := fakeHubFunc(t, func(rw http.ResponseWriter, r *http.Request) {
		if inm := r.Header.Get("If-None-Match"); inm != "" {
			rw.Header().Set("ETag", inm)
			rw.WriteHeader(http.StatusNotModified)
			return
		}
		http.Error(rw, "no", 503)
	})
	first, _ := newAgentURLs(t, w, ModeVerify, []string{live.URL}, []string{live.Pin})
	if o := cycle(t, first); o.Result != ResultVerified {
		t.Fatalf("%+v", o)
	}
	p2 := w.Publish(agenttest.Options{})
	for name, lagging := range map[string]struct{ url, pin string }{"same bundle": {same, samePin}, "304": {notMod, notModPin}} {
		a, _ := newAgentURLs(t, w, ModeVerify, []string{lagging.url, live.URL}, []string{lagging.pin, live.Pin})
		os.RemoveAll(w.StateDir)
		// A state that has verified the first bundle.
		if o := cycle(t, mustAgentOn(t, w, same, samePin)); o.Result != ResultVerified {
			t.Fatalf("%s setup: %+v", name, o)
		}
		o := cycle(t, a)
		if o.Result != ResultVerified || o.Hub != live.URL || mustState(t, w).Verified.Commit != p2.Commit {
			t.Fatalf("%s: %+v", name, o)
		}
	}
	// With every hub lagging the answer is "unchanged" from the first of them.
	a, _ := newAgentURLs(t, w, ModeVerify, []string{notMod, same}, []string{notModPin, samePin})
	if o := cycle(t, a); o.Result != ResultUnchanged || o.Hub != notMod {
		t.Fatalf("%+v", o)
	}
}

func mustAgentOn(t *testing.T, w *agenttest.World, url, pin string) *Agent {
	a, _ := newAgentURLs(t, w, ModeVerify, []string{url}, []string{pin})
	return a
}

func TestApplyWritesLockSinceLikeInfraPull(t *testing.T) {
	if ApplyTimeout > 1800*time.Second {
		t.Errorf("ApplyTimeout %s is beyond infra-pull's LOCK_MAX", ApplyTimeout)
	}
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	w.Publish(agenttest.Options{})
	a, clk := newAgent(t, w, ModeApply, hub)
	since := filepath.Join(filepath.Dir(a.InfraLock), "lock.since")
	seen := filepath.Join(w.Dir, "seen")
	stub := filepath.Join(w.Dir, "peek")
	os.WriteFile(stub, []byte("#!/bin/sh\ncat "+since+" > "+seen+"\nls "+since+".new > "+seen+".new 2>/dev/null\nexit 0\n"), 0o755)
	a.Ansible = stub
	if o := cycle(t, a); o.Result != ResultOK {
		t.Fatalf("%+v", o)
	}
	got, _ := os.ReadFile(seen)
	if string(got) != fmt.Sprintf("%d\n", clk.t.Unix()) {
		t.Errorf("lock.since during the run: %q, want %d and a newline", got, clk.t.Unix())
	}
	if _, err := os.Stat(seen + ".new"); err == nil {
		if b, _ := os.ReadFile(seen + ".new"); len(b) != 0 {
			t.Errorf("lock.since.new existed during the run")
		}
	}
	for _, p := range []string{since, since + ".new"} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s is left behind", p)
		}
	}
}

func TestKillGroupSkipsAGroupThatIsGone(t *testing.T) {
	cmd := newTrue(t)
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if killGroup(cmd.Process.Pid, syscall.SIGKILL) {
		t.Error("signalled a group that does not exist")
	}
}

func TestLockDirIsPrivate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "infra", "lock")
	f, err := LockFile(context.Background(), p, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if st, _ := os.Stat(filepath.Dir(p)); st.Mode().Perm() != 0o700 {
		t.Errorf("mode %v", st.Mode())
	}
}

func TestReleasesDirIsCheckedLikeTheStateDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := PrepareDir(dir); err != nil {
		t.Fatal(err)
	}
	rel := filepath.Join(dir, "releases")
	os.Chmod(rel, 0o755)
	err := PrepareDir(dir)
	if !isConfigError(err) || !strings.Contains(err.Error(), rel) {
		t.Fatalf("err %v", err)
	}
	if st, _ := os.Stat(rel); st.Mode().Perm() != 0o755 {
		t.Errorf("releases was chmodded to %v", st.Mode())
	}
}

func TestAnInterruptedCycleIsErrInterrupted(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	w.Publish(agenttest.Options{})
	a, _ := newAgent(t, w, ModeVerify, hub)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.Cycle(ctx); !errors.Is(err, ErrInterrupted) {
		t.Fatalf("err %v", err)
	}
}

func newTrue(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("true")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd
}

func TestApplyEnvPassesTheRestartFile(t *testing.T) {
	env := applyEnv([]string{"PATH=/bin", RestartFileEnv + "=/inherited", "INFRA_AGENT_TOKEN=x", "SOPS_AGE_KEY_FILE=/old"}, "/age", "/state/restart-requested")
	want := []string{"PATH=/bin", "SOPS_AGE_KEY_FILE=/age", RestartFileEnv + "=/state/restart-requested"}
	if strings.Join(env, "\n") != strings.Join(want, "\n") {
		t.Errorf("env %q", env)
	}
	if RestartFile("/var/lib/infra-agent") != "/var/lib/infra-agent/restart-requested" {
		t.Error(RestartFile("/var/lib/infra-agent"))
	}
}

// A configuration run that changes the agent (binary, settings or unit) must not restart the service from inside its own
// ansible: it creates the restart request file, and the loop exits after the cycle, once the result is saved and reported.
func TestLoopExitsOnARestartRequest(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	p := w.Publish(agenttest.Options{})
	a, _ := newAgent(t, w, ModeApply, hub)
	a.Cfg.Interval = 100 * time.Millisecond
	seen := filepath.Join(w.Dir, "seen-restart-file")
	stub := filepath.Join(w.Dir, "ansible-requests-restart")
	os.WriteFile(stub, []byte("#!/bin/sh\nprintf '%s' \"$"+RestartFileEnv+"\" > "+seen+"\ntouch \"$"+RestartFileEnv+"\"\n"), 0o755)
	a.Ansible = stub

	done := make(chan bool, 1)
	go func() { done <- a.Loop(context.Background()) }()
	var restart bool
	select {
	case restart = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Loop did not return after the restart request")
	}
	if !restart {
		t.Fatal("Loop returned false")
	}
	if got, _ := os.ReadFile(seen); string(got) != RestartFile(w.StateDir) {
		t.Errorf("ansible saw %s=%q", RestartFileEnv, got)
	}
	if _, err := os.Lstat(RestartFile(w.StateDir)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the request was not removed: %v", err)
	}
	st := mustState(t, w)
	if st.LastResult != ResultOK || st.Applied == nil || st.Applied.Commit != p.Commit {
		t.Errorf("the cycle before the restart was not recorded: %+v", st)
	}
	if rep, ok := hub.Report(t); !ok || rep.Result != "ok" {
		t.Errorf("the cycle before the restart was not reported: %+v", rep)
	}
}

func TestLoopIgnoresARequestItCannotRemove(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	w.Publish(agenttest.Options{})
	a, _ := newAgent(t, w, ModeVerify, hub)
	a.Cfg.Interval = 50 * time.Millisecond
	// A non-empty directory exists but cannot be removed: honouring it would exit after every cycle.
	os.MkdirAll(filepath.Join(RestartFile(w.StateDir), "x"), 0o700)
	if a.takeRestartRequest() {
		t.Fatal("an unremovable request was honoured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	if a.Loop(ctx) {
		t.Error("Loop returned for a restart")
	}
	if st := mustState(t, w); st.LastCycle == nil {
		t.Error("no cycle ran")
	}
}

// A request left over from before the process started is not one for it: the loop removes it and keeps running (verify
// mode, so no ansible run creates a new one).
func TestLoopRemovesAStaleRequestAtStart(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	w.Publish(agenttest.Options{})
	a, _ := newAgent(t, w, ModeVerify, hub)
	a.Cfg.Interval = 50 * time.Millisecond
	os.MkdirAll(w.StateDir, 0o700)
	os.WriteFile(RestartFile(w.StateDir), nil, 0o600)
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	if a.Loop(ctx) {
		t.Fatal("Loop returned for a stale request")
	}
	if _, err := os.Lstat(RestartFile(w.StateDir)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the stale request is still there: %v", err)
	}
	if st := mustState(t, w); st.LastCycle == nil {
		t.Error("no cycle ran")
	}
}
