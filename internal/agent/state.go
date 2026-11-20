package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"filippo.io/age"

	"github.com/KazuhaHub/infra-hub/internal/atomicfile"
)

// Identity is the host's age identity (or identities, if the file holds several).
type Identity struct {
	ids []age.Identity
	pub []string
}

// LoadIdentity reads an age key file (comments are allowed, as in the SOPS key files).
func LoadIdentity(path string) (*Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("age key: %w", err)
	}
	defer f.Close()
	ids, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("age key %s: %v", path, err) // the message names no key material
	}
	out := &Identity{ids: ids}
	for _, id := range ids {
		if x, ok := id.(*age.X25519Identity); ok {
			out.pub = append(out.pub, x.Recipient().String())
		}
	}
	return out, nil
}

// Recipients are the public keys of the identity (only X25519 ones are listed).
func (i *Identity) Recipients() []string { return i.pub }

// Record is a bundle the agent has seen: its commit and statement time, and when the agent did what it did.
type Record struct {
	Commit string    `json:"commit"`
	Time   time.Time `json:"time"` // the statement time
	At     time.Time `json:"at"`   // when it was applied or verified
}

// State is what survives between cycles, in <state dir>/state.json.
type State struct {
	APIVersion string `json:"apiVersion"`
	// Applied is the last bundle that ansible applied successfully.
	Applied *Record `json:"applied,omitempty"`
	// Verified is the newest bundle that passed every check and was extracted. It is where the forward-only rule
	// starts, and what a 304 refers to.
	Verified    *Record    `json:"verified,omitempty"`
	LastResult  string     `json:"lastResult,omitempty"`
	LastMessage string     `json:"lastMessage,omitempty"`
	LastHub     string     `json:"lastHub,omitempty"`
	LastCycle   *time.Time `json:"lastCycle,omitempty"`
}

// statePath is the state file in dir.
func statePath(dir string) string { return filepath.Join(dir, "state.json") }

// LoadState reads the state; a missing file is an empty state. A file that does not parse is an error and is never
// silently replaced: the forward-only protection would be lost with it.
func LoadState(dir string) (State, error) {
	data, err := os.ReadFile(statePath(dir))
	if errors.Is(err, fs.ErrNotExist) {
		return State{APIVersion: "v1"}, nil
	}
	if err != nil {
		return State{}, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return State{}, fmt.Errorf("%s does not parse (remove it after checking it, the agent then forgets what it applied): %v", statePath(dir), err)
	}
	if s.APIVersion != "v1" {
		return State{}, fmt.Errorf("%s has apiVersion %q, this agent reads v1", statePath(dir), s.APIVersion)
	}
	return s, nil
}

// Save writes the state atomically.
func (s State) Save(dir string) error {
	s.APIVersion = "v1"
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(statePath(dir), append(data, '\n'), 0o600)
}

// ErrLocked means another agent holds the lock.
var ErrLocked = errors.New("another infra-agent is running")

// Lock is an exclusive flock on <state dir>/lock, held until Close (or until the process ends).
type Lock struct{ f *os.File }

// PrepareDir makes sure the state directory exists: it creates a missing one (0700, with releases/ inside), and refuses
// one that exists but is not a real directory owned by the user running the agent with mode 0700. It never changes the
// mode or the owner of an existing directory: that would hide a mistake that exposes the state (or the way to it).
func PrepareDir(dir string) error {
	if err := ensurePrivateDir(dir); err != nil {
		return err
	}
	return ensurePrivateDir(filepath.Join(dir, "releases"))
}

// ensurePrivateDir creates dir (0700) if it is missing, and otherwise checks it: a real directory, owned by the
// user running the agent, mode 0700. It changes nothing that exists.
func ensurePrivateDir(dir string) error {
	st, err := os.Lstat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return os.MkdirAll(dir, 0o700)
	case err != nil:
		return err
	}
	if !st.IsDir() {
		return configErrorf("state directory %s is not a directory", dir)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != os.Geteuid() {
		return configErrorf("state directory %s is owned by uid %d, not by uid %d that runs the agent", dir, sys.Uid, os.Geteuid())
	}
	if st.Mode().Perm() != 0o700 {
		return configErrorf("state directory %s has mode %04o, it must be 0700", dir, st.Mode().Perm())
	}
	return nil
}

// ErrLockTimeout means the lock was still held when the wait ended.
var ErrLockTimeout = errors.New("lock timeout")

// lockPoll is how often a lock that is held is tried again (a variable for tests).
var lockPoll = 250 * time.Millisecond

// LockFile takes an exclusive flock on path, creating the file (and its directory) if needed, and waits up to timeout for
// another holder to let go. It returns ErrLockTimeout on timeout and ctx.Err() if ctx ends first.
func LockFile(ctx context.Context, path string, timeout time.Duration) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			f.Close()
			return nil, err
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, ErrLockTimeout
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(lockPoll):
		}
	}
}

// AcquireLock takes the lock without waiting.
func AcquireLock(dir string) (*Lock, error) {
	if err := PrepareDir(dir); err != nil {
		return nil, err
	}
	p := filepath.Join(dir, "lock")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w (lock %s is held)", ErrLocked, p)
		}
		return nil, err
	}
	return &Lock{f: f}, nil
}

// Close releases the lock.
func (l *Lock) Close() error { return l.f.Close() }
