package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/agenttest"
	"github.com/KazuhaHub/infra-hub/internal/githubapp"
	"github.com/KazuhaHub/infra-hub/internal/githubapp/githubapptest"
)

func TestGitHubFallbackWithApp(t *testing.T) {
	w := agenttest.NewWorld(t)
	p := w.Publish(agenttest.Options{})
	clock := githubapptest.NewClock()
	api := githubapptest.NewAPI(t, "4242", clock.Now)
	git := githubapptest.NewGit(t, api)
	git.Seed(t, "acme/infra", w.MirrorRepo)
	keyFile := filepath.Join(t.TempDir(), "github-app.pem")
	if err := os.WriteFile(keyFile, api.KeyPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	githubTestAPI, githubTestGitBase = api.URL, git.Server.URL
	t.Cleanup(func() { githubTestAPI, githubTestGitBase = "", "" })

	// No deploy key and no known_hosts exist anywhere: only the App can carry this fetch. The URL is the ssh form.
	a := githubAgent(t, w, ModeApply, "git@github.com:acme/infra.git", agenttest.DeadURL(t), agenttest.DeadURL(t))
	a.Cfg.GitHubAppID, a.Cfg.GitHubAppKey = "4242", keyFile
	src, err := githubapp.NewSource("4242", keyFile, a.Cfg.GitHubRepo)
	if err != nil {
		t.Fatal(err)
	}
	src.API, src.GitBase, src.Now = api.URL, git.Server.URL, clock.Now
	a.ghSource = src

	o := cycle(t, a)
	if o.Result != ResultOK || o.Hub != GitHubSource || !strings.HasPrefix(o.Message, "from GitHub, no hub gave a bundle") {
		t.Fatalf("outcome %+v", o)
	}
	if st := mustState(t, w); st.Verified == nil || st.Verified.Commit != p.Commit || st.LastHub != GitHubSource {
		t.Errorf("state %+v", st)
	}
	iss := api.Issued()
	if len(iss) != 1 || iss[0].Repo != "acme/infra" || len(iss[0].Perms) != 1 || iss[0].Perms["contents"] != "read" {
		t.Fatalf("issued %+v", iss)
	}
	// Same bundle again: nothing new, and the token is reused.
	if o := cycle(t, a); o.Result != ResultUnchanged || o.Hub != GitHubSource {
		t.Errorf("second cycle %+v", o)
	}
	if len(api.Issued()) != 1 {
		t.Errorf("token not reused: %d issued", len(api.Issued()))
	}
	// After the token's lifetime a new one is issued and accepted.
	clock.Advance(2 * time.Hour)
	if o := cycle(t, a); o.Result != ResultUnchanged || o.Hub != GitHubSource {
		t.Errorf("third cycle %+v", o)
	}
	if len(api.Issued()) != 2 || git.Denied() != 0 {
		t.Errorf("issued %d, denied %d", len(api.Issued()), git.Denied())
	}
	// The token is nowhere on disk in the repository.
	cfgData, _ := os.ReadFile(filepath.Join(githubDir(w.StateDir), "config"))
	for _, i := range api.Issued() {
		if strings.Contains(string(cfgData), i.Token) {
			t.Error("token in the repository config")
		}
	}
}

func TestGitHubFallbackAppFailureIsReported(t *testing.T) {
	w := agenttest.NewWorld(t)
	w.Publish(agenttest.Options{})
	api := githubapptest.NewAPI(t, "4242", nil) // the repository is not installed
	githubTestAPI, githubTestGitBase = api.URL, api.URL
	t.Cleanup(func() { githubTestAPI, githubTestGitBase = "", "" })
	keyFile := filepath.Join(t.TempDir(), "k.pem")
	os.WriteFile(keyFile, api.KeyPEM(), 0o600)
	a := githubAgent(t, w, ModeApply, "https://github.com/acme/infra.git", agenttest.DeadURL(t))
	a.Cfg.GitHubAppID, a.Cfg.GitHubAppKey = "4242", keyFile
	o := cycle(t, a)
	if o.Result != ResultUnreachable || !strings.Contains(o.Message, "GitHub fallback") || !strings.Contains(o.Message, "installed") {
		t.Fatalf("outcome %+v", o)
	}
}

func TestConfigGitHubApp(t *testing.T) {
	tok := testToken(t)
	good := "INFRA_AGENT_TOKEN=" + tok + "\nINFRA_AGENT_HOST=web1\nINFRA_AGENT_GITHUB_REPO=git@github.com:KazuhaHub/infra.git\n"
	c, err := LoadConfig(writeEnv(t, good+"INFRA_AGENT_GITHUB_APP_ID=4242\n"), nil)
	if err != nil || c.GitHubAppID != "4242" || c.GitHubAppKey != DefaultGitHubAppKey {
		t.Fatalf("defaults: %+v, %v", c, err)
	}
	c, err = LoadConfig(writeEnv(t, strings.Replace(good, "git@github.com:KazuhaHub/infra.git", "https://github.com/KazuhaHub/infra.git", 1)+"INFRA_AGENT_GITHUB_APP_ID=4242\nINFRA_AGENT_GITHUB_APP_KEY=/k/app.pem\n"), nil)
	if err != nil || c.GitHubAppKey != "/k/app.pem" {
		t.Fatalf("https url: %+v, %v", c, err)
	}
	// The old ssh settings next to the App are ignored (a host mid-migration).
	if c, err = LoadConfig(writeEnv(t, good+"INFRA_AGENT_GITHUB_APP_ID=4242\nINFRA_AGENT_GITHUB_KEY=/old\n"), nil); err != nil || c.GitHubAppID != "4242" {
		t.Fatalf("with old key: %+v, %v", c, err)
	}
	// An https URL without the App is still refused: only ssh carries the deploy-key fallback.
	if _, err = LoadConfig(writeEnv(t, strings.Replace(good, "git@github.com:KazuhaHub/infra.git", "https://github.com/KazuhaHub/infra.git", 1)), nil); err == nil {
		t.Error("https without the App accepted")
	}
	base := "INFRA_AGENT_TOKEN=" + tok + "\nINFRA_AGENT_HOST=web1\n"
	for name, env := range map[string]string{
		"app id without repo": base + "INFRA_AGENT_GITHUB_APP_ID=4242\n",
		"app key without id":  good + "INFRA_AGENT_GITHUB_APP_KEY=/k\n",
		"bad app id":          good + "INFRA_AGENT_GITHUB_APP_ID=abc\n",
		"other host":          strings.Replace(good, "github.com", "git.example.org", 1) + "INFRA_AGENT_GITHUB_APP_ID=4242\n",
		"relative key":        good + "INFRA_AGENT_GITHUB_APP_ID=4242\nINFRA_AGENT_GITHUB_APP_KEY=k.pem\n",
	} {
		if _, err := LoadConfig(writeEnv(t, env), nil); err == nil || !isConfigError(err) {
			t.Errorf("%s: err %v", name, err)
		}
	}
}

func TestCheckGitHubFilesApp(t *testing.T) {
	dir := t.TempDir()
	c := Config{GitHubRepo: "git@github.com:a/b.git", GitHubAppID: "1", GitHubAppKey: filepath.Join(dir, "k.pem")}
	if err := c.CheckGitHubFiles(); err == nil || !isConfigError(err) {
		t.Fatalf("missing key: %v", err)
	}
	os.WriteFile(c.GitHubAppKey, []byte("junk"), 0o600)
	if err := c.CheckGitHubFiles(); err == nil {
		t.Fatal("junk key accepted")
	}
	api := githubapptest.NewAPI(t, "1", nil)
	os.WriteFile(c.GitHubAppKey, api.KeyPEM(), 0o600)
	if err := c.CheckGitHubFiles(); err != nil {
		t.Fatal(err)
	}
}

// A token failure is not repository damage: the cached github.git stays.
func TestGitHubAppAuthFailureKeepsTheCache(t *testing.T) {
	w := agenttest.NewWorld(t)
	w.Publish(agenttest.Options{})
	api := githubapptest.NewAPI(t, "4242", nil)
	git := githubapptest.NewGit(t, api)
	git.Seed(t, "acme/infra", w.MirrorRepo)
	githubTestAPI, githubTestGitBase = api.URL, git.Server.URL
	t.Cleanup(func() { githubTestAPI, githubTestGitBase = "", "" })
	keyFile := filepath.Join(t.TempDir(), "k.pem")
	os.WriteFile(keyFile, api.KeyPEM(), 0o600)
	a := githubAgent(t, w, ModeApply, "git@github.com:acme/infra.git", agenttest.DeadURL(t))
	a.Cfg.GitHubAppID, a.Cfg.GitHubAppKey = "4242", keyFile
	if o := cycle(t, a); o.Result != ResultOK {
		t.Fatalf("first cycle %+v", o)
	}
	marker := filepath.Join(githubDir(w.StateDir), "marker")
	os.WriteFile(marker, []byte("x"), 0o600)
	other := githubapptest.NewAPI(t, "4242", nil)
	os.WriteFile(keyFile, other.KeyPEM(), 0o600) // not the App's key
	if o := cycle(t, a); o.Result != ResultUnreachable {
		t.Fatalf("bad key %+v", o)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Error("an auth failure wiped the cached repository")
	}
}
