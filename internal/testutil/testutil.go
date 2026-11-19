// Package testutil holds helpers shared by the tests: git repositories and SSH keys.
package testutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

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

// NewKey is NewKeyPriv without the private key.
func NewKey(t *testing.T) (ssh.Signer, string) {
	s, line, _ := NewKeyPriv(t)
	return s, line
}

// NewKeyPriv makes an ed25519 key and returns it as a signer, an authorized_keys line and the private key.
func NewKeyPriv(t *testing.T) (ssh.Signer, string, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey()))), priv
}

// WritePrivateKey writes priv as an OpenSSH private key file for the ssh binary.
func WritePrivateKey(t *testing.T, path string, priv ed25519.PrivateKey) {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
}
