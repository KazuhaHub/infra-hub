package state

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/atomicfile"
)

// HostReport is the latest report an agent sent; the fields are those of the API and of `status -o json`.
type HostReport struct {
	AppliedCommit string           `json:"appliedCommit,omitempty"` // empty: nothing applied yet
	Result        string           `json:"result"`                  // ok, failed, verified, rejected, unreachable or unchanged
	Message       string           `json:"message,omitempty"`
	Time          string           `json:"time"` // RFC 3339, as the agent stated it
	Features      []FeatureSummary `json:"features,omitempty"`
	// RejectedHubs are the hubs that served the agent a bundle it rejected in that cycle (hub URLs).
	RejectedHubs []string `json:"rejectedHubs,omitempty"`
	ReceivedAt   string   `json:"receivedAt"` // RFC 3339 UTC, the hub's clock
}

// FeatureSummary is the outcome of one feature in a report.
type FeatureSummary struct {
	Name    string `json:"name"`
	Result  string `json:"result"` // ok, failed or skipped
	Message string `json:"message,omitempty"`
}

type stateFile struct {
	// MirrorLastSuccess is the last time the mirror fetched from upstream successfully (shown by `infra-hub status`).
	MirrorLastSuccess time.Time `json:"mirror_last_success"`
	// Reports is the latest report per host. Older files also have a "hosts" object (last-seen times of the removed SSH
	// server); it is ignored on load and not written.
	Reports map[string]HostReport `json:"reports,omitempty"`
}

// State keeps the mirror time and the latest report per host in memory and in a small JSON file. Setters only mark the
// state dirty; Flush (called every few seconds and on shutdown) writes it, so a busy hub does not rewrite the file per request.
type State struct {
	path string
	now  func() time.Time

	wmu     sync.Mutex // serialises Flush, so an older copy never lands after a newer one
	mu      sync.Mutex
	reports map[string]HostReport
	mirror  time.Time
	dirty   bool
	writes  int
}

// LoadState reads path; a missing file is an empty state. A damaged file is an error (the caller starts empty).
func LoadState(path string) (*State, error) {
	s := &State{path: path, now: time.Now, reports: map[string]HostReport{}}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	var f stateFile
	if err := json.Unmarshal(data, &f); err != nil {
		return s, fmt.Errorf("state file %s: %w", path, err)
	}
	s.mirror = f.MirrorLastSuccess
	if f.Reports != nil {
		s.reports = f.Reports
	}
	return s, nil
}

// SetReport stores the latest report of a host (replacing the previous one) and marks the state dirty.
func (s *State) SetReport(host string, r HostReport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reports[host] = r
	s.dirty = true
}

// Reports is a copy of the stored reports.
func (s *State) Reports() map[string]HostReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]HostReport, len(s.reports))
	for k, v := range s.reports {
		out[k] = v
	}
	return out
}

// SetMirrorSuccess records a successful upstream fetch.
func (s *State) SetMirrorSuccess(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mirror = t.UTC().Truncate(time.Second)
	s.dirty = true
}

// MirrorSuccess is the last recorded successful upstream fetch (zero if none was ever recorded).
func (s *State) MirrorSuccess() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mirror
}

// Flush writes the file if anything changed. On error the state stays dirty and is tried again.
func (s *State) Flush() error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	data, err := json.MarshalIndent(stateFile{MirrorLastSuccess: s.mirror, Reports: s.reports}, "", "  ")
	s.dirty = false
	s.mu.Unlock()
	if err == nil {
		err = atomicfile.Write(s.path, append(data, '\n'), 0o644)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.dirty = true
		return err
	}
	s.writes++
	return nil
}
