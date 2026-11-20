package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/bundle"
	"github.com/KazuhaHub/infra-hub/internal/gitmirror"
)

// GitHubSource is the name of the GitHub fallback where a hub's URL would be (Outcome.Hub, the state's last hub).
const GitHubSource = "github"

// GitHubTimeout bounds one fetch from GitHub.
const GitHubTimeout = 3 * time.Minute

// githubDir is the bare repository the fallback fetches main-attestation into.
func githubDir(stateDir string) string { return filepath.Join(stateDir, "github.git") }

// allowFileProtocol lets tests use a local path as the repository. It is never set outside tests.
var allowFileProtocol = false

// githubBundleError is a GitHub tree that does not hold a usable bundle (a missing file, one over its limit, a bad
// statement): a bad bundle, not a transport failure.
type githubBundleError struct{ err error }

func (e *githubBundleError) Error() string { return e.err.Error() }
func (e *githubBundleError) Unwrap() error { return e.err }

// fetchGitHub fetches main-attestation from the configured repository and reads the three files at its tip. Nothing is
// trusted yet: the caller runs the same checks as for a bundle from a hub. A killed git can leave lock files behind and a
// repository can be damaged (a damaged object at an unchanged tip looks like a bad tree); the repository is only a
// cache, so after any failure it is removed and everything is tried once more. Only if that fails too is the error
// reported (a githubBundleError means the bundle itself is bad).
func (a *Agent) fetchGitHub(ctx context.Context) (bundle.Files, error) {
	files, err := a.fetchGitHubOnce(ctx)
	if err == nil || ctx.Err() != nil {
		return files, err
	}
	slog.Warn("GitHub fetch failed, starting again from an empty repository", "err", err)
	if rerr := os.RemoveAll(githubDir(a.Cfg.StateDir)); rerr != nil {
		return files, fmt.Errorf("%w (and cannot remove the repository: %v)", err, rerr)
	}
	return a.fetchGitHubOnce(ctx)
}

func (a *Agent) fetchGitHubOnce(ctx context.Context) (bundle.Files, error) {
	cfg := a.Cfg
	dir := githubDir(cfg.StateDir)
	ctx, cancel := context.WithTimeout(ctx, GitHubTimeout)
	defer cancel()
	env := gitmirror.GitEnv(
		"GIT_DIR="+dir,
		fmt.Sprintf("GIT_SSH_COMMAND=ssh -F /dev/null -i %s -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=yes -o GlobalKnownHostsFile=/dev/null -o UserKnownHostsFile=%s", cfg.GitHubKey, cfg.GitHubKnownHosts),
	)
	// Only ssh may carry the fetch (a local path only in tests).
	transports := []string{"-c", "protocol.allow=never", "-c", "protocol.ssh.allow=always"}
	if allowFileProtocol {
		transports = append(transports, "-c", "protocol.file.allow=always")
	}
	git := func(args ...string) error {
		cmd := exec.CommandContext(ctx, "git", append(append([]string{}, transports...), args...)...)
		cmd.Env = env
		cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
		cmd.WaitDelay = 10 * time.Second
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Run(); err != nil {
			if ctx.Err() != nil {
				return fmt.Errorf("git %s: %w", args[0], ctx.Err())
			}
			return fmt.Errorf("git %s: %v: %s", args[0], err, truncate(strings.TrimSpace(out.String()), 300))
		}
		return nil
	}
	if _, err := os.Stat(filepath.Join(dir, "HEAD")); err != nil {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return bundle.Files{}, err
		}
		if err := git("init", "--bare", "--quiet"); err != nil {
			return bundle.Files{}, err
		}
	}
	if err := git("fetch", "--quiet", "--force", "--no-tags", "--depth=1", "--", cfg.GitHubRepo, "+"+bundle.AttestationRef+":"+bundle.AttestationRef); err != nil {
		return bundle.Files{}, err
	}
	l, err := bundle.Load(ctx, dir, bundle.DefaultLimits)
	if err != nil {
		if errors.Is(err, bundle.ErrNoBundle) {
			err = &githubBundleError{err}
		}
		return bundle.Files{}, err
	}
	return l.Files, nil
}
