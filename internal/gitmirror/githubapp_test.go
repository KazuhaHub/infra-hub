package gitmirror_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/githubapp"
	"github.com/KazuhaHub/infra-hub/internal/githubapp/githubapptest"
	"github.com/KazuhaHub/infra-hub/internal/gitmirror"
	"github.com/KazuhaHub/infra-hub/internal/testutil"
)

type ghWorld struct {
	api   *githubapptest.API
	git   *githubapptest.Git
	clock *githubapptest.Clock
	work  string
	src   *githubapp.Source
	m     *gitmirror.Mirror
}

func newGHWorld(t *testing.T) *ghWorld {
	t.Helper()
	w := &ghWorld{clock: githubapptest.NewClock()}
	w.api = githubapptest.NewAPI(t, "4242", w.clock.Now)
	w.git = githubapptest.NewGit(t, w.api)
	upstream, work := testutil.MakeUpstream(t)
	w.work = work
	w.git.Seed(t, "acme/infra", upstream)
	keyFile := filepath.Join(t.TempDir(), "github_app_key")
	if err := os.WriteFile(keyFile, w.api.KeyPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := githubapp.NewSource("4242", keyFile, "git@github.com:acme/infra.git")
	if err != nil {
		t.Fatal(err)
	}
	src.API, src.GitBase, src.Now = w.api.URL, w.git.Server.URL, w.clock.Now
	w.src = src
	w.m = &gitmirror.Mirror{Repo: filepath.Join(t.TempDir(), "infra.git"), Upstream: "git@github.com:acme/infra.git", GitHub: src}
	return w
}

func TestMirrorFetchesWithAppTokenAndRefreshesIt(t *testing.T) {
	w := newGHWorld(t)
	ctx := context.Background()
	if err := w.m.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	refs, _ := gitmirror.ReadRefs(ctx, w.m.Repo)
	if len(refs) != 2 || refs["refs/heads/main"] == "" {
		t.Fatalf("refs %v", refs)
	}
	iss := w.api.Issued()
	if len(iss) != 1 || iss[0].Repo != "acme/infra" || len(iss[0].Perms) != 1 || iss[0].Perms["contents"] != "read" {
		t.Fatalf("issued %+v (want one token for acme/infra, contents: read only)", iss)
	}
	// The token is reused while it is fresh.
	w.clock.Advance(30 * time.Minute)
	testutil.RunGit(t, w.work, "commit", "-q", "--allow-empty", "-m", "c2")
	w.pushToServer(t)
	if err := w.m.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(w.api.Issued()); n != 1 || w.api.Lookups() != 1 {
		t.Fatalf("%d tokens, %d lookups after 30 min", n, w.api.Lookups())
	}
	// Five minutes before expiry it is replaced, and the server (which checks expiry) accepts the new one.
	w.clock.Advance(26 * time.Minute)
	if err := w.m.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(w.api.Issued()); n != 2 || w.api.Lookups() != 1 {
		t.Fatalf("%d tokens, %d lookups after 56 min", n, w.api.Lookups())
	}
	// Long after the first token expired, fetching still works.
	w.clock.Advance(3 * time.Hour)
	if err := w.m.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(w.api.Issued()); n != 3 {
		t.Fatalf("%d tokens", n)
	}
	if w.git.Denied() != 0 {
		t.Errorf("the git server refused %d requests", w.git.Denied())
	}
}

func (w *ghWorld) pushToServer(t *testing.T) {
	t.Helper()
	dir := filepath.Join(w.git.Root, "acme", "infra.git")
	testutil.RunGit(t, dir, "fetch", "-q", w.work, "+refs/heads/*:refs/heads/*")
}

func TestMirrorTokenNeverInArgvLogsOrConfig(t *testing.T) {
	w := newGHWorld(t)
	// A git in front of the real one that records its arguments.
	real, err := exec.LookPath("git")
	if err != nil {
		t.Skip(err)
	}
	shimDir := t.TempDir()
	argLog := filepath.Join(shimDir, "argv.log")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" >> " + argLog + "\nexec " + real + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(shimDir, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	var skew time.Duration
	w.src.Now = func() time.Time { return w.clock.Now().Add(skew) }
	ctx := context.Background()
	if err := w.m.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	// A fetch the server refuses (the source's clock runs behind the server's, so it sends an expired token).
	w.clock.Advance(2 * time.Hour)
	skew = -90 * time.Minute
	ferr := w.m.Fetch(ctx)
	if ferr == nil {
		t.Fatal("an expired token must be refused")
	}
	slog.Error("mirror fetch failed", "err", ferr)

	var secrets []string
	for _, i := range w.api.Issued() {
		secrets = append(secrets, i.Token)
	}
	if len(secrets) < 1 {
		t.Fatal("no token issued")
	}
	argv, _ := os.ReadFile(argLog)
	cfgData, _ := os.ReadFile(filepath.Join(w.m.Repo, "config"))
	for _, tok := range secrets {
		b64 := githubappBasic(tok)
		for name, hay := range map[string]string{"argv": string(argv), "logs": logs.String(), "error": ferr.Error(), "repo config": string(cfgData)} {
			if strings.Contains(hay, tok) || strings.Contains(hay, b64) {
				t.Errorf("token %s found in %s", tok, name)
			}
		}
	}
	if !strings.Contains(string(argv), "/acme/infra.git") || strings.Contains(string(argv), "x-access-token") {
		t.Errorf("argv: %s", argv)
	}
	if strings.Contains(string(argv), "@") {
		t.Errorf("the remote URL must not carry credentials: %s", argv)
	}
}

func githubappBasic(tok string) string {
	return base64Std("x-access-token:" + tok)
}

func TestMirrorAppFailures(t *testing.T) {
	w := newGHWorld(t)
	// Not installed on the repository.
	good := w.m.GitHub
	other, _ := githubapp.NewSource("4242", w.src.KeyFile, "git@github.com:acme/other.git")
	other.API, other.GitBase, other.Now = w.src.API, w.src.GitBase, w.clock.Now
	w.m.GitHub = other
	err := w.m.Fetch(context.Background())
	if err == nil || !strings.Contains(err.Error(), "installed") {
		t.Fatalf("err %v", err)
	}
	w.m.GitHub = good
	// A key that is not the App's.
	bad := githubapptest.NewAPI(t, "4242", w.clock.Now)
	if err := os.WriteFile(w.src.KeyFile, bad.KeyPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := w.m.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("err %v", err)
	}
	// The key file changed back: it is picked up without a restart.
	if err := os.WriteFile(w.src.KeyFile, w.api.KeyPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := w.m.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestMirrorWithoutAppStillUsesUpstream(t *testing.T) {
	upstream, _ := testutil.MakeUpstream(t)
	m := &gitmirror.Mirror{Repo: filepath.Join(t.TempDir(), "infra.git"), Upstream: upstream}
	if err := m.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func base64Std(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// The inherited environment never reaches a git that carries a token.
func TestGitEnvIsClean(t *testing.T) {
	for _, k := range []string{"GIT_TRACE", "GIT_TRACE_CURL", "GIT_CURL_VERBOSE", "GIT_TRACE_REDACT", "GIT_SSL_NO_VERIFY", "GIT_CONFIG_PARAMETERS", "GIT_ASKPASS", "SSH_ASKPASS", "GIT_EXTERNAL_DIFF"} {
		t.Setenv(k, "1")
	}
	for _, e := range gitmirror.GitEnv("X=1") {
		name, _, _ := strings.Cut(e, "=")
		switch name {
		case "PATH", "HOME", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL", "GIT_TERMINAL_PROMPT", "X":
		default:
			t.Errorf("unexpected variable %s", e)
		}
	}
}
