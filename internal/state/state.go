package state

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/atomicfile"
)

// NodeRecord is what the hub remembers about one client host.
type NodeRecord struct {
	LastSeen        time.Time `json:"last_seen"`
	Main            string    `json:"main,omitempty"`             // main as shown to the host's last fetch
	MainAttestation string    `json:"main_attestation,omitempty"` // main-attestation, likewise
}

type stateFile struct {
	// MirrorLastSuccess is the last time the mirror fetched from upstream successfully (shown by `infra-hub status`).
	MirrorLastSuccess time.Time             `json:"mirror_last_success"`
	Hosts             map[string]NodeRecord `json:"hosts"` // keyed by host name
}

// State keeps the per-host records in memory and in a small JSON file. Touch only marks the state dirty; Flush
// (called every few seconds and on shutdown) writes it, so a busy hub does not rewrite the file per request.
type State struct {
	path string
	now  func() time.Time

	mu     sync.Mutex
	hosts  map[string]NodeRecord
	mirror time.Time
	dirty  bool
	writes int
}

// LoadState reads path; a missing file is an empty state. A damaged file is an error (the caller starts empty).
func LoadState(path string) (*State, error) {
	s := &State{path: path, now: time.Now, hosts: map[string]NodeRecord{}}
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
	if f.Hosts != nil {
		s.hosts = f.Hosts
	}
	return s, nil
}

// Touch records that the host was just seen; refs (may be nil) are the refs the hub holds at that moment.
func (s *State) Touch(host string, refs map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.hosts[host]
	r.LastSeen = s.now().UTC().Truncate(time.Second)
	if refs != nil {
		r.Main = refs["refs/heads/main"]
		r.MainAttestation = refs["refs/heads/main-attestation"]
	}
	s.hosts[host] = r
	s.dirty = true
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

// Snapshot is a copy of the records.
func (s *State) Snapshot() map[string]NodeRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]NodeRecord, len(s.hosts))
	for k, v := range s.hosts {
		out[k] = v
	}
	return out
}

// Flush writes the file if anything changed. On error the state stays dirty and is tried again.
func (s *State) Flush() error {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	data, err := json.MarshalIndent(stateFile{MirrorLastSuccess: s.mirror, Hosts: s.hosts}, "", "  ")
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
