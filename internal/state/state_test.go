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
	when := time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)
	for i := 0; i < 100; i++ { // many updates, no write until Flush
		s.SetMirrorSuccess(when)
		s.SetReport("host-a", HostReport{Result: "ok", ReceivedAt: "2026-11-19T08:00:01Z"})
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("a setter wrote the file")
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
	if !again.MirrorSuccess().Equal(when) || again.Reports()["host-a"].Result != "ok" {
		t.Fatalf("after reload: %v %+v", again.MirrorSuccess(), again.Reports())
	}
}

func TestStateWriteIsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s, _ := LoadState(path)
	s.SetReport("host-a", HostReport{Result: "ok"})
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
			if err != nil || json.Unmarshal(data, &f) != nil || len(f.Reports) == 0 {
				t.Errorf("reader saw a bad file: %v %q", err, data)
				return
			}
		}
	}()
	for i := 0; i < 300; i++ {
		s.SetReport("host-a", HostReport{Result: "ok", Message: strings.Repeat("a", i)})
		s.SetReport("host-b", HostReport{Result: "failed"})
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
	s.SetReport("host-a", HostReport{Result: "ok"})
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	s.path = filepath.Join(dir, "missing-dir", "state.json") // the temp file cannot be created there
	s.SetReport("host-b", HostReport{Result: "ok"})
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
	if again, _ := LoadState(path); len(again.Reports()) != 2 {
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
	// An old state file with the last-seen records of the SSH server loads, and the records are not written back.
	os.WriteFile(path, []byte(`{"mirror_last_success":"2026-11-19T08:00:00Z","hosts":{"h1":{"last_seen":"2026-11-19T08:00:00Z","main":"abc"}}}`), 0o644)
	old, err := LoadState(path)
	if err != nil || len(old.Reports()) != 0 || old.MirrorSuccess().IsZero() {
		t.Fatalf("old file: %v", err)
	}
	old.SetReport("h1", HostReport{Result: "ok"})
	if err := old.Flush(); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); strings.Contains(string(data), "last_seen") {
		t.Errorf("the old records were written back:\n%s", data)
	}
}
