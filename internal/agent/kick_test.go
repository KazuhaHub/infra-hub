package agent

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/agenttest"
)

const kickCommit = "0123456789abcdef0123456789abcdef01234567"

func runLoop(t *testing.T, a *Agent) (stop func()) {
	t.Helper()
	a.noStartDelay = true
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Loop(ctx); close(done) }()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("Loop did not stop")
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

func waitVerified(t *testing.T, w *agenttest.World, commit string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := LoadState(w.StateDir); err == nil && st.Verified != nil && st.Verified.Commit == commit {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s was not verified in time", commit)
}

// A new bundle on the hub starts a cycle at once although the interval is an hour.
func TestKickStartsACycleBeforeTheInterval(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	p1 := w.Publish(agenttest.Options{})
	a, _ := newAgent(t, w, ModeVerify, hub)
	a.Cfg.Interval = time.Hour
	a.MinCycleGap = 50 * time.Millisecond
	runLoop(t, a)
	waitVerified(t, w, p1.Commit)
	time.Sleep(200 * time.Millisecond) // the agent is now holding a wait request
	p2 := w.Publish(agenttest.Options{})
	hub.Bundles.Poke()
	waitVerified(t, w, p2.Commit)
	// and once more, to see that it keeps waiting after a kick
	p3 := w.Publish(agenttest.Options{})
	hub.Bundles.Poke()
	waitVerified(t, w, p3.Commit)
}

// kickAgent is an agent over one fake hub whose /v1/wait is the given handler; every other path answers 503.
func kickAgent(t *testing.T, wait http.HandlerFunc) *Agent {
	t.Helper()
	w := agenttest.NewWorld(t)
	url, pin := fakeHubFunc(t, func(rw http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/wait/") {
			wait(rw, r)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(503)
		_, _ = rw.Write([]byte(`{"apiVersion":"v1","error":{"code":"no_bundle","message":"x"}}`))
	})
	a, _ := newAgentURLs(t, w, ModeVerify, []string{url}, []string{pin})
	return a
}

func TestWaitKickChanged(t *testing.T) {
	a := kickAgent(t, func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("etag") != kickCommit {
			t.Errorf("etag %q", r.URL.Query().Get("etag"))
		}
		_, _ = rw.Write([]byte(`{"apiVersion":"v1","changed":true,"commit":"` + strings.Repeat("ab", 20) + `"}`))
	})
	ok, commit := a.waitKick(context.Background(), kickCommit, time.Now().Add(5*time.Second))
	if !ok || commit != strings.Repeat("ab", 20) {
		t.Fatalf("%v %q", ok, commit)
	}
}

func TestWaitKickAnOlderHubIsLeftAlone(t *testing.T) {
	var n atomic.Int32
	a := kickAgent(t, func(rw http.ResponseWriter, r *http.Request) {
		n.Add(1)
		rw.WriteHeader(404) // what a hub before v0.12 answers for an unknown path
		_, _ = rw.Write([]byte(`{"apiVersion":"v1","error":{"code":"not_found","message":"no such path"}}`))
	})
	start := time.Now()
	ok, _ := a.waitKick(context.Background(), kickCommit, time.Now().Add(400*time.Millisecond))
	if ok {
		t.Fatal("kicked by a hub without the endpoint")
	}
	if took := time.Since(start); took < 350*time.Millisecond {
		t.Errorf("returned after %v, it should sleep out the interval", took)
	}
	if n.Load() != 1 || !a.Hubs[0].kickSuspended(time.Now()) {
		t.Errorf("%d requests, suspended %v", n.Load(), a.Hubs[0].kickSuspended(time.Now()))
	}
	// asked again: no request at all while suspended
	a.waitKick(context.Background(), kickCommit, time.Now().Add(100*time.Millisecond))
	if n.Load() != 1 {
		t.Errorf("a suspended hub was asked again (%d requests)", n.Load())
	}
}

func TestWaitKickErrorsBackOffAndNeverBusyLoop(t *testing.T) {
	var n atomic.Int32
	a := kickAgent(t, func(rw http.ResponseWriter, r *http.Request) {
		n.Add(1)
		rw.WriteHeader(500)
	})
	start := time.Now()
	ok, _ := a.waitKick(context.Background(), kickCommit, time.Now().Add(500*time.Millisecond))
	if ok || n.Load() != 1 {
		t.Fatalf("kicked %v after %d requests, want one request and a back-off", ok, n.Load())
	}
	if time.Since(start) < 450*time.Millisecond {
		t.Error("returned before the interval was over")
	}
}

func TestWaitKickTimeoutsAreSpacedByTheMinimumGap(t *testing.T) {
	var n atomic.Int32
	a := kickAgent(t, func(rw http.ResponseWriter, r *http.Request) {
		n.Add(1) // answers "no change" at once, as a hub with a tiny timeout would
		_, _ = rw.Write([]byte(`{"apiVersion":"v1","changed":false}`))
	})
	a.MinCycleGap = 100 * time.Millisecond
	ok, _ := a.waitKick(context.Background(), kickCommit, time.Now().Add(550*time.Millisecond))
	if ok {
		t.Fatal("kicked")
	}
	if got := n.Load(); got < 3 || got > 7 {
		t.Errorf("%d requests in 550 ms with a gap of 100 ms", got)
	}
}

func TestWaitKickStopsWithTheContext(t *testing.T) {
	released := make(chan struct{})
	a := kickAgent(t, func(rw http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		close(released)
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool, 1)
	go func() { ok, _ := a.waitKick(ctx, kickCommit, time.Now().Add(time.Hour)); done <- ok }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case ok := <-done:
		if ok {
			t.Error("kicked")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("waitKick did not stop")
	}
	select {
	case <-released: // the connection was closed, so the hub frees its slot
	case <-time.After(3 * time.Second):
		t.Error("the request was not abandoned")
	}
}

func TestWaitKickRejectsMalformedAnswers(t *testing.T) {
	for name, body := range map[string]string{
		"no apiVersion":   `{"changed":false}`,
		"no changed":      `{"apiVersion":"v1"}`,
		"changed no hash": `{"apiVersion":"v1","changed":true,"commit":"zz"}`,
		"not json":        `<html>`,
	} {
		t.Run(name, func(t *testing.T) {
			a := kickAgent(t, func(rw http.ResponseWriter, r *http.Request) { _, _ = rw.Write([]byte(body)) })
			if _, _, err := a.Hubs[0].Wait(context.Background(), "web1", ""); err == nil {
				t.Error("accepted")
			}
		})
	}
}

// After a kick whose bundle the agent could not verify, the next wait starts from the commit the hub named, so a hub
// that compares with it does not answer at once again (no loop of cycles).
func TestLoopWaitsFromTheCommitOfTheLastKick(t *testing.T) {
	var mu sync.Mutex
	var etags []string
	a := kickAgent(t, func(rw http.ResponseWriter, r *http.Request) {
		etag := r.URL.Query().Get("etag")
		mu.Lock()
		etags = append(etags, etag)
		mu.Unlock()
		if etag != kickCommit {
			_, _ = rw.Write([]byte(`{"apiVersion":"v1","changed":true,"commit":"` + kickCommit + `"}`))
			return
		}
		<-r.Context().Done()
	})
	a.Cfg.Interval = time.Hour
	a.MinCycleGap = 50 * time.Millisecond
	stop := runLoop(t, a)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(etags)
		mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond) // a loop would show up as more requests
	stop()
	mu.Lock()
	defer mu.Unlock()
	if len(etags) != 2 || etags[0] != "" || etags[1] != kickCommit {
		t.Errorf("etags %q", etags)
	}
}
