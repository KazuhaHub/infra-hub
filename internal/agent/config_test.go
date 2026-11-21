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

const testIDs = "INFRA_AGENT_SIGSTORE_REPO_ID=1462297697\nINFRA_AGENT_SIGSTORE_OWNER_ID=165913136\n"

// writeEnv writes agent.env; the Sigstore IDs, which are required, are added unless the content sets them.
func writeEnv(t *testing.T, content string) string {
	t.Helper()
	if !strings.Contains(content, "SIGSTORE_REPO_ID") {
		content += testIDs
	}
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
	if c.Host != "web1" || c.AgeKey != DefaultAgeKey || c.Mode != ModeVerify || c.Interval != 5*time.Minute ||
		c.StateDir != DefaultStateDir || c.Repo != DefaultRepo || len(c.Token.Hubs) != 2 || c.Token.Hubs[0] != "https://hub1.example.org:8443" {
		t.Errorf("%+v", c)
	}
	p = writeEnv(t, "INFRA_AGENT_TOKEN="+tok+"\nINFRA_AGENT_HOST=web1\nINFRA_AGENT_MODE=apply\nINFRA_AGENT_INTERVAL=90s\nINFRA_AGENT_STATE_DIR=/srv/ia\nINFRA_AGENT_AGE_KEY=/k\nINFRA_AGENT_SIGNERS=/s\nINFRA_AGENT_SIGNATURE=either\n")
	c, err = LoadConfig(p, func(k string) (string, bool) { // the environment wins
		if k == "INFRA_AGENT_MODE" {
			return "verify", true
		}
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != ModeVerify || c.Interval != 90*time.Second || c.StateDir != "/srv/ia" || c.AgeKey != "/k" || len(c.Warnings) != 2 {
		t.Errorf("%+v", c)
	}
}

// fileRepos lets the test use a local path as the GitHub repository.
func fileRepos(t *testing.T) {
	t.Helper()
	allowFileProtocol = true
	t.Cleanup(func() { allowFileProtocol = false })
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
	c, err = LoadConfig(writeEnv(t, good), func(k string) (string, bool) {
		return "ssh://git@git.example.org/infra.git", k == "INFRA_AGENT_GITHUB_REPO"
	})
	if err != nil || c.GitHubRepo != "ssh://git@git.example.org/infra.git" {
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

func TestConfigSigstoreSettings(t *testing.T) {
	tok := testToken(t)
	base := "INFRA_AGENT_TOKEN=" + tok + "\nINFRA_AGENT_HOST=web1\n"
	for name, c := range map[string]struct{ extra, want string }{
		"no repo id":    {"INFRA_AGENT_SIGSTORE_OWNER_ID=2\n", "SIGSTORE_REPO_ID is required"},
		"no owner id":   {"INFRA_AGENT_SIGSTORE_REPO_ID=1\n", "SIGSTORE_OWNER_ID is required"},
		"neither":       {"", "SIGSTORE_REPO_ID is required"},
		"bad owner id":  {"INFRA_AGENT_SIGSTORE_REPO_ID=1\nINFRA_AGENT_SIGSTORE_OWNER_ID=abc\n", "SIGSTORE_OWNER_ID"},
		"unknown value": {testIDs + "INFRA_AGENT_SIGNATURE=gpg\n", "want sigstore"},
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "agent.env")
			if err := os.WriteFile(p, []byte(base+c.extra), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadConfig(p, nil)
			if err == nil || !isConfigError(err) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %v, want %q", err, c.want)
			}
		})
	}
}

func TestConfigLegacySignatureSettingsWarn(t *testing.T) {
	tok := testToken(t)
	base := "INFRA_AGENT_TOKEN=" + tok + "\nINFRA_AGENT_HOST=web1\n"
	for _, v := range []string{"ssh", "either"} {
		c, err := LoadConfig(writeEnv(t, base+"INFRA_AGENT_SIGNATURE="+v+"\n"), nil)
		if err != nil || len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], "deprecated") {
			t.Errorf("%s: %v %v", v, err, c.Warnings)
		}
	}
	c, err := LoadConfig(writeEnv(t, base+"INFRA_AGENT_SIGNATURE=sigstore\n"), nil)
	if err != nil || len(c.Warnings) != 0 {
		t.Errorf("sigstore: %v %v", err, c.Warnings)
	}
	c, err = LoadConfig(writeEnv(t, base+"INFRA_AGENT_SIGNERS=/etc/infra/allowed_signers\n"), nil)
	if err != nil || len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], "SIGNERS is ignored") {
		t.Errorf("signers: %v %v", err, c.Warnings)
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
		"repo with space":     {good + "INFRA_AGENT_GITHUB_REPO=a b\n", "not an ssh git URL"},
		"repo https":          {good + "INFRA_AGENT_GITHUB_REPO=https://github.com/KazuhaHub/infra.git\n", "not an ssh git URL"},
		"repo local path":     {good + "INFRA_AGENT_GITHUB_REPO=/srv/infra.git\n", "not an ssh git URL"},
		"repo ext transport":  {good + "INFRA_AGENT_GITHUB_REPO=ext::sh -c x\n", "not an ssh git URL"},
		"key with space":      {good + "INFRA_AGENT_GITHUB_REPO=git@github.com:a/b.git\nINFRA_AGENT_GITHUB_KEY=/etc/my key\n", "only letters"},
		"key with quote":      {good + "INFRA_AGENT_GITHUB_REPO=git@github.com:a/b.git\nINFRA_AGENT_GITHUB_KEY=/etc/k';id;'\n", "only letters"},
		"hosts with dollar":   {good + "INFRA_AGENT_GITHUB_REPO=git@github.com:a/b.git\nINFRA_AGENT_GITHUB_KNOWN_HOSTS=/etc/$HOME\n", "only letters"},
		"repo as option":      {good + "INFRA_AGENT_GITHUB_REPO=--upload-pack=x\n", "not an ssh git URL"},
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
	c := Config{AgeKey: filepath.Join(dir, "age.key")}
	if _, err := c.CheckFiles(); err == nil || !isConfigError(err) {
		t.Fatalf("missing age key: %v", err)
	}
	os.WriteFile(c.AgeKey, []byte("not a key\n"), 0o600)
	if _, err := c.CheckFiles(); err == nil || !isConfigError(err) || strings.Contains(err.Error(), "not a key") {
		t.Fatalf("bad age key: %v", err)
	}
}
