// Package gitmirror keeps the read-only bare copy of the upstream repository.
package gitmirror

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// mirrorRefspecs are the only refs the mirror carries.
var mirrorRefspecs = []string{
	"+refs/heads/main:refs/heads/main",
	"+refs/heads/main-attestation:refs/heads/main-attestation",
}

// Mirror keeps a bare copy of main and main-attestation. Serving it stale is safe: clients check the
// attestation themselves and only move forward.
type Mirror struct {
	Repo     string
	Upstream string
	Interval time.Duration
	// OnSuccess (optional) is called after every successful fetch, e.g. to persist the time for `infra-hub status`.
	OnSuccess func(time.Time)

	Now    func() time.Time // tests; nil means time.Now
	mu     sync.Mutex
	lastOK time.Time // in memory only: a restarted hub has fetched nothing yet
}

func (m *Mirror) clock() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Fresh returns nil if the last successful fetch since this process started is at most max old. A hub that has not
// fetched yet (or whose fetches keep failing) must not serve: its refs may be arbitrarily old.
func (m *Mirror) Fresh(max time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastOK.IsZero() {
		return errors.New("no successful fetch from upstream since the hub started")
	}
	if age := m.clock().Sub(m.lastOK); age > max {
		return fmt.Errorf("last successful fetch from upstream was %s ago (limit %s)", age.Round(time.Second), max)
	}
	return nil
}

// GitEnv is the environment for every git child process: no user or system config and no prompts.
func GitEnv(extra ...string) []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=/nonexistent",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_TERMINAL_PROMPT=0",
	}
	return append(env, extra...)
}

// sshCommand is how the mirror reaches GitHub: the deploy key that systemd handed over (LoadCredential=), and a
// known_hosts file from the same place.
func sshCommand() string {
	dir := os.Getenv("CREDENTIALS_DIRECTORY")
	if dir == "" {
		return ""
	}
	cmd := fmt.Sprintf("ssh -F /dev/null -i %s -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes", filepath.Join(dir, "deploy_key"))
	if _, err := os.Stat(filepath.Join(dir, "known_hosts")); err == nil {
		cmd += " -o UserKnownHostsFile=" + filepath.Join(dir, "known_hosts")
	}
	return cmd
}

// Fetch runs one fetch and records its success time.
func (m *Mirror) Fetch(ctx context.Context) error {
	if err := m.fetch(ctx); err != nil {
		return err
	}
	now := m.clock()
	m.mu.Lock()
	m.lastOK = now
	m.mu.Unlock()
	if m.OnSuccess != nil {
		m.OnSuccess(now)
	}
	return nil
}

// fetch creates the bare repo if needed and runs one `git fetch --prune` with the explicit refspecs.
func (m *Mirror) fetch(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	if _, err := os.Stat(filepath.Join(m.Repo, "HEAD")); err != nil {
		if err := os.MkdirAll(filepath.Dir(m.Repo), 0o755); err != nil {
			return err
		}
		if out, err := m.git(ctx, "", "init", "--bare", "--quiet", "--initial-branch=main", m.Repo); err != nil {
			return fmt.Errorf("git init: %v: %s", err, out)
		}
	}
	args := append([]string{"fetch", "--quiet", "--prune", "--force", "--no-tags", m.Upstream}, mirrorRefspecs...)
	if out, err := m.git(ctx, m.Repo, args...); err != nil {
		return fmt.Errorf("git fetch: %v: %s", err, lastLines(out, 2))
	}
	return nil
}

func (m *Mirror) git(ctx context.Context, gitDir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	env := GitEnv()
	if gitDir != "" {
		env = append(env, "GIT_DIR="+gitDir)
	}
	if s := sshCommand(); s != "" {
		env = append(env, "GIT_SSH_COMMAND="+s)
	}
	cmd.Env = env
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	return buf.String(), err
}

// Run fetches now and then every Interval until ctx ends. A failed fetch is logged and tried again next time.
func (m *Mirror) Run(ctx context.Context) {
	for {
		if err := m.Fetch(ctx); err != nil && ctx.Err() == nil {
			log.Printf("mirror: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(m.Interval):
		}
	}
}

// ReadRefs returns refname -> commit for the branches of the bare repo.
func ReadRefs(ctx context.Context, repo string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "for-each-ref", "--format=%(objectname) %(refname)", "refs/heads/")
	cmd.Env = GitEnv("GIT_DIR=" + repo)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	refs := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if sha, ref, ok := strings.Cut(line, " "); ok {
			refs[ref] = sha
		}
	}
	return refs, nil
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " ")
}
