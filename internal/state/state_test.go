package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestStateRoundTripAndThrottle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, _ := LoadState(path)
	for i := 0; i < 100; i++ { // many requests, no write until Flush
		s.Touch("host-a", map[string]string{"refs/heads/main": "aaa", "refs/heads/main-attestation": "bbb"})
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("Touch wrote the file")
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err != nil { // nothing changed: no second write
		t.Fatal(err)
	}
	if s.writes != 1 {
		t.Fatalf("writes = %d, want 1", s.writes)
	}
	again, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	r := again.Snapshot()["host-a"]
	if r.Main != "aaa" || r.MainAttestation != "bbb" || r.LastSeen.IsZero() {
		t.Fatalf("record = %+v", r)
	}
	s.Touch("host-a", nil) // refs unknown: the last known ones stay
	if got := s.Snapshot()["host-a"].Main; got != "aaa" {
		t.Fatalf("main = %q", got)
	}
}

func TestStateWriteIsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s, _ := LoadState(path)
	s.now = func() time.Time { return time.Unix(1700000000, 0) }
	s.Touch("host-a", nil)
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // a reader that must never see a partial file
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			data, err := os.ReadFile(path)
			var f stateFile
			if err != nil || json.Unmarshal(data, &f) != nil || len(f.Hosts) == 0 {
				t.Errorf("reader saw a bad file: %v %q", err, data)
				return
			}
		}
	}()
	for i := 0; i < 300; i++ {
		s.Touch("host-a", map[string]string{"refs/heads/main": strings.Repeat("a", 40)})
		s.Touch("host-b", nil)
		if err := s.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}
}

func TestStateFailedWriteKeepsOldFileAndStaysDirty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s, _ := LoadState(path)
	s.Touch("host-a", nil)
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	s.path = filepath.Join(dir, "missing-dir", "state.json") // the temp file cannot be created there
	s.Touch("host-b", nil)
	if err := s.Flush(); err == nil {
		t.Fatal("expected an error")
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("old file changed")
	}
	s.path = path
	if err := s.Flush(); err != nil { // still dirty: the next flush writes it
		t.Fatal(err)
	}
	if again, _ := LoadState(path); len(again.Snapshot()) != 2 {
		t.Fatal("host-b missing after retry")
	}
}

func TestLoadStateDamagedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	os.WriteFile(path, []byte("{not json"), 0o644)
	if s, err := LoadState(path); err == nil || s == nil {
		t.Fatalf("want an error and a usable empty state, got %v %v", s, err)
	}
}

func TestReportsPersistAndReplace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	s, _ := LoadState(path)
	s.SetReport("h1", HostReport{AppliedCommit: "a", Result: "ok", Time: "2026-11-19T08:00:00Z", ReceivedAt: "2026-11-19T08:00:01Z"})
	s.SetReport("h1", HostReport{AppliedCommit: "b", Result: "failed", Time: "2026-11-19T08:05:00Z", ReceivedAt: "2026-11-19T08:05:01Z"})
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	again, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if r := again.Reports(); len(r) != 1 || r["h1"].AppliedCommit != "b" || r["h1"].Result != "failed" {
		t.Errorf("reports after reload: %+v", r)
	}
	// An old state file without reports still loads.
	os.WriteFile(path, []byte(`{"mirror_last_success":"2026-11-19T08:00:00Z","hosts":{}}`), 0o644)
	if old, err := LoadState(path); err != nil || len(old.Reports()) != 0 {
		t.Errorf("old file: %v", err)
	}
}
