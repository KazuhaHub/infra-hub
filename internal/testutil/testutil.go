// Package testutil holds helpers shared by the tests: git repositories.
package testutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KazuhaHub/infra-hub/internal/gitmirror"
)

// NeedTool skips the test when a tool is not installed.
func NeedTool(t *testing.T, names ...string) {
	t.Helper()
	for _, n := range names {
		if _, err := exec.LookPath(n); err != nil {
			t.Skipf("%s not installed", n)
		}
	}
}

// RunGit runs git in dir with a clean environment and returns its trimmed output.
func RunGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(gitmirror.GitEnv(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid", "GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=commit.gpgsign", "GIT_CONFIG_VALUE_0=false")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// MakeUpstream builds a bare repo (named upstream.git) with main, main-attestation and an extra branch.
func MakeUpstream(t *testing.T) (bare string, work string) {
	t.Helper()
	NeedTool(t, "git")
	dir := t.TempDir()
	work = filepath.Join(dir, "work")
	RunGit(t, dir, "init", "-q", "-b", "main", work)
	os.WriteFile(filepath.Join(work, "f"), []byte("1\n"), 0o644)
	RunGit(t, work, "add", "f")
	RunGit(t, work, "commit", "-q", "-m", "c1")
	RunGit(t, work, "branch", "main-attestation")
	RunGit(t, work, "branch", "other")
	bare = filepath.Join(dir, "upstream.git")
	RunGit(t, dir, "clone", "-q", "--bare", work, bare)
	return bare, work
}
