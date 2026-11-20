package agent

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/jointoken"
)

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}

const testPin = "sha256//TcM7RUikMFbA2YvjlGf/AZCdVHFGtTRo/xPiTbyB/X4="

func testToken(t *testing.T) string {
	t.Helper()
	tok, err := jointoken.Encode([]string{testPin}, []string{"https://hub1.example.org:8443", "https://192.0.2.10:8443"})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func writeEnv(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "agent.env")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func isConfigError(err error) bool {
	var ce *ConfigError
	return errors.As(err, &ce)
}

func TestConfigDefaultsAndValues(t *testing.T) {
	tok := testToken(t)
	p := writeEnv(t, "# comment\n\nINFRA_AGENT_TOKEN="+tok+"\nINFRA_AGENT_HOST=\"web1\"\n")
	c, err := LoadConfig(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Host != "web1" || c.AgeKey != DefaultAgeKey || c.Signers != DefaultSigners || c.Mode != ModeVerify || c.Interval != 5*time.Minute ||
		c.StateDir != DefaultStateDir || c.Repo != DefaultRepo || len(c.Token.Hubs) != 2 || c.Token.Hubs[0] != "https://hub1.example.org:8443" {
		t.Errorf("%+v", c)
	}
	p = writeEnv(t, "INFRA_AGENT_TOKEN="+tok+"\nINFRA_AGENT_HOST=web1\nINFRA_AGENT_MODE=apply\nINFRA_AGENT_INTERVAL=90s\nINFRA_AGENT_STATE_DIR=/srv/ia\nINFRA_AGENT_AGE_KEY=/k\nINFRA_AGENT_SIGNERS=/s\n")
	c, err = LoadConfig(p, func(k string) (string, bool) { // the environment wins
		if k == "INFRA_AGENT_MODE" {
			return "verify", true
		}
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != ModeVerify || c.Interval != 90*time.Second || c.StateDir != "/srv/ia" || c.AgeKey != "/k" || c.Signers != "/s" {
		t.Errorf("%+v", c)
	}
}

func TestConfigGitHubFallback(t *testing.T) {
	tok := testToken(t)
	good := "INFRA_AGENT_TOKEN=" + tok + "\nINFRA_AGENT_HOST=web1\n"
	c, err := LoadConfig(writeEnv(t, good), nil)
	if err != nil || c.GitHubRepo != "" {
		t.Fatalf("a three-line file: %+v, %v", c, err)
	}
	c, err = LoadConfig(writeEnv(t, good+"INFRA_AGENT_GITHUB_REPO=git@github.com:KazuhaHub/infra.git\n"), nil)
	if err != nil || c.GitHubRepo != "git@github.com:KazuhaHub/infra.git" || c.GitHubKey != DefaultGitHubKey || c.GitHubKnownHosts != DefaultGitHubKnownHosts {
		t.Fatalf("defaults: %+v, %v", c, err)
	}
	c, err = LoadConfig(writeEnv(t, good+"INFRA_AGENT_GITHUB_REPO=git@github.com:KazuhaHub/infra.git\nINFRA_AGENT_GITHUB_KEY=/k\nINFRA_AGENT_GITHUB_KNOWN_HOSTS=/h\n"), nil)
	if err != nil || c.GitHubKey != "/k" || c.GitHubKnownHosts != "/h" {
		t.Fatalf("values: %+v, %v", c, err)
	}
	// An empty repo means off, and the environment can turn it on.
	if c, err = LoadConfig(writeEnv(t, good+"INFRA_AGENT_GITHUB_REPO=\n"), nil); err != nil || c.GitHubRepo != "" {
		t.Fatalf("empty: %+v, %v", c, err)
	}
	c, err = LoadConfig(writeEnv(t, good), func(k string) (string, bool) { return "/srv/infra.git", k == "INFRA_AGENT_GITHUB_REPO" })
	if err != nil || c.GitHubRepo != "/srv/infra.git" {
		t.Fatalf("environment: %+v, %v", c, err)
	}
}

func TestCheckGitHubFiles(t *testing.T) {
	dir := t.TempDir()
	if err := (Config{}).CheckGitHubFiles(); err != nil {
		t.Fatalf("off: %v", err)
	}
	c := Config{GitHubRepo: "x", GitHubKey: filepath.Join(dir, "key"), GitHubKnownHosts: filepath.Join(dir, "hosts")}
	if err := c.CheckGitHubFiles(); err == nil || !isConfigError(err) {
		t.Fatalf("missing key: %v", err)
	}
	os.WriteFile(c.GitHubKey, []byte("k"), 0o600)
	if err := c.CheckGitHubFiles(); err == nil || !strings.Contains(err.Error(), "known_hosts") {
		t.Fatalf("missing known_hosts: %v", err)
	}
	os.WriteFile(c.GitHubKnownHosts, []byte("h"), 0o600)
	if err := c.CheckGitHubFiles(); err != nil {
		t.Fatal(err)
	}
}

func TestConfigErrors(t *testing.T) {
	tok := testToken(t)
	good := "INFRA_AGENT_TOKEN=" + tok + "\nINFRA_AGENT_HOST=web1\n"
	cases := map[string]struct{ content, want string }{
		"unknown key":         {good + "INFRA_AGENT_TOKN=x\n", "unknown setting INFRA_AGENT_TOKN"},
		"foreign key":         {good + "PATH=/bin\n", "unknown setting PATH"},
		"missing token":       {"INFRA_AGENT_HOST=web1\n", "INFRA_AGENT_TOKEN is required"},
		"missing host":        {"INFRA_AGENT_TOKEN=" + tok + "\n", "INFRA_AGENT_HOST is required"},
		"bad token":           {"INFRA_AGENT_TOKEN=ih1.abc\nINFRA_AGENT_HOST=web1\n", "INFRA_AGENT_TOKEN"},
		"not a token":         {"INFRA_AGENT_TOKEN=hello\nINFRA_AGENT_HOST=web1\n", "join token"},
		"bad mode":            {good + "INFRA_AGENT_MODE=yolo\n", "want verify or apply"},
		"bad interval":        {good + "INFRA_AGENT_INTERVAL=soon\n", "INFRA_AGENT_INTERVAL"},
		"short interval":      {good + "INFRA_AGENT_INTERVAL=1s\n", "shorter than"},
		"duplicate":           {good + "INFRA_AGENT_HOST=web2\n", "set twice"},
		"no equals":           {good + "oops\n", "KEY=VALUE"},
		"bad host":            {"INFRA_AGENT_TOKEN=" + tok + "\nINFRA_AGENT_HOST=--limit\n", "not a plain host name"},
		"relative path":       {good + "INFRA_AGENT_AGE_KEY=age.key\n", "must be absolute"},
		"relative state":      {good + "INFRA_AGENT_STATE_DIR=state\n", "must be absolute"},
		"key without repo":    {good + "INFRA_AGENT_GITHUB_KEY=/k\n", "GITHUB_KEY is set without"},
		"hosts without repo":  {good + "INFRA_AGENT_GITHUB_KNOWN_HOSTS=/h\n", "GITHUB_KNOWN_HOSTS is set without"},
		"repo with space":     {good + "INFRA_AGENT_GITHUB_REPO=a b\n", "not a git URL"},
		"repo as option":      {good + "INFRA_AGENT_GITHUB_REPO=--upload-pack=x\n", "not a git URL"},
		"relative github key": {good + "INFRA_AGENT_GITHUB_REPO=git@github.com:KazuhaHub/infra.git\nINFRA_AGENT_GITHUB_KEY=k\n", "must be absolute"},
		"host with slash":     {"INFRA_AGENT_TOKEN=" + tok + "\nINFRA_AGENT_HOST=a/b\n", "not a plain host name"},
		"host with space":     {"INFRA_AGENT_TOKEN=" + tok + "\nINFRA_AGENT_HOST=a b\n", "not a plain host name"},
		"host with newline":   {"INFRA_AGENT_TOKEN=" + tok + "\nINFRA_AGENT_HOST=a\\nb\n", "not a plain host name"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := LoadConfig(writeEnv(t, c.content), nil)
			if err == nil || !isConfigError(err) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %v (config error %v), want %q", err, isConfigError(err), c.want)
			}
		})
	}
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "absent.env"), nil); err == nil || !isConfigError(err) {
		t.Errorf("a missing env file: %v", err)
	}
}

func TestCheckFiles(t *testing.T) {
	dir := t.TempDir()
	c := Config{AgeKey: filepath.Join(dir, "age.key"), Signers: filepath.Join(dir, "signers")}
	if _, err := c.CheckFiles(); err == nil || !isConfigError(err) {
		t.Fatalf("missing age key: %v", err)
	}
	os.WriteFile(c.AgeKey, []byte("not a key\n"), 0o600)
	if _, err := c.CheckFiles(); err == nil || !isConfigError(err) || strings.Contains(err.Error(), "not a key") {
		t.Fatalf("bad age key: %v", err)
	}
}
