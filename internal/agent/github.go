package agent

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// fetchGitHub fetches main-attestation from the configured repository and reads the three files at its tip. Nothing is
// trusted yet: the caller runs the same checks as for a bundle from a hub.
func (a *Agent) fetchGitHub(ctx context.Context) (bundle.Files, error) {
	cfg := a.Cfg
	dir := githubDir(cfg.StateDir)
	ctx, cancel := context.WithTimeout(ctx, GitHubTimeout)
	defer cancel()
	env := gitmirror.GitEnv(
		"GIT_DIR="+dir,
		fmt.Sprintf("GIT_SSH_COMMAND=ssh -F /dev/null -i %s -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=%s", cfg.GitHubKey, cfg.GitHubKnownHosts),
	)
	git := func(args ...string) error {
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Env = env
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
		return bundle.Files{}, err
	}
	return l.Files, nil
}
