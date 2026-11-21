package githubapp_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/KazuhaHub/infra-hub/internal/githubapp"
	"github.com/KazuhaHub/infra-hub/internal/githubapp/githubapptest"
)

func TestParseRepo(t *testing.T) {
	for _, u := range []string{
		"git@github.com:KazuhaHub/infra.git", "git@github.com:KazuhaHub/infra", "ssh://git@github.com/KazuhaHub/infra.git",
		"https://github.com/KazuhaHub/infra.git", "https://github.com/KazuhaHub/infra",
	} {
		if o, r, err := githubapp.ParseRepo(u); err != nil || o != "KazuhaHub" || r != "infra" {
			t.Errorf("%s: %q %q %v", u, o, r, err)
		}
	}
	for _, u := range []string{
		"", "git@gitlab.com:a/b.git", "http://github.com/a/b.git", "https://github.com/a", "https://github.com/a/b/c",
		"https://user:pw@github.com/a/b.git", "https://evil.example/github.com/a/b.git", "/srv/repo", "-oProxyCommand=x",
		"https://github.com/../b", "git@github.com:a/..",
	} {
		if _, _, err := githubapp.ParseRepo(u); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
}

func TestPlainHTTPOnlyToLoopback(t *testing.T) {
	clock := githubapptest.NewClock()
	api := githubapptest.NewAPI(t, "7", clock.Now)
	key := filepath.Join(t.TempDir(), "k")
	if err := os.WriteFile(key, api.KeyPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ api, git string }{{"http://example.org", ""}, {"", "http://example.org"}, {"ftp://127.0.0.1", ""}} {
		s, err := githubapp.NewSource("7", key, "git@github.com:a/b.git")
		if err != nil {
			t.Fatal(err)
		}
		s.API, s.GitBase = c.api, c.git
		if _, err := s.GitEnv(context.Background()); err == nil || !strings.Contains(err.Error(), "http") {
			t.Errorf("%+v: err %v", c, err)
		}
	}
}

func TestOverridesMustPairLoopbackFakes(t *testing.T) {
	clock := githubapptest.NewClock()
	api := githubapptest.NewAPI(t, "7", clock.Now)
	key := filepath.Join(t.TempDir(), "k")
	os.WriteFile(key, api.KeyPEM(), 0o600)
	// A fake API with the real github.com (or the reverse) would send a token somewhere it should not go.
	for _, c := range []struct{ api, git string }{{api.URL, ""}, {"", api.URL}, {api.URL, "https://github.com.evil.example"}} {
		s, _ := githubapp.NewSource("7", key, "git@github.com:a/b.git")
		s.API, s.GitBase = c.api, c.git
		if _, err := s.GitEnv(context.Background()); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
}

func TestConcurrentTokenRequestsShareOneRequest(t *testing.T) {
	clock := githubapptest.NewClock()
	api := githubapptest.NewAPI(t, "7", clock.Now)
	api.Install("a/b")
	key, _ := githubapp.ParseKey(api.KeyPEM())
	app, err := githubapp.New(githubapp.Options{AppID: "7", Key: key, API: api.URL, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	toks := make([]string, 16)
	for i := range toks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			if toks[i], err = app.Token(context.Background(), "a", "b"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	for _, tk := range toks {
		if tk == "" || tk != toks[0] {
			t.Fatalf("tokens differ: %v", toks)
		}
	}
	if n := len(api.Issued()); n != 1 {
		t.Errorf("%d tokens issued for one burst", n)
	}
	// A different repository is not held up by this one.
	if _, err := app.Token(context.Background(), "a", "nope"); err == nil {
		t.Error("an uninstalled repository got a token")
	}
}

func TestNewSourceChecksButOpensNothing(t *testing.T) {
	if _, err := githubapp.NewSource("12", "/does/not/exist", "git@github.com:a/b.git"); err != nil {
		t.Fatal(err)
	}
	for _, c := range [][3]string{{"", "/k", "git@github.com:a/b.git"}, {"x1", "/k", "git@github.com:a/b.git"}, {"1", "", "git@github.com:a/b.git"}, {"1", "/k", "git@example.org:a/b.git"}} {
		if _, err := githubapp.NewSource(c[0], c[1], c[2]); err == nil {
			t.Errorf("%v accepted", c)
		}
	}
}

func TestGitEnvScopesTheHeaderToTheHost(t *testing.T) {
	clock := githubapptest.NewClock()
	api := githubapptest.NewAPI(t, "7", clock.Now)
	api.Install("a/b")
	key := filepath.Join(t.TempDir(), "k")
	os.WriteFile(key, api.KeyPEM(), 0o600)
	s, _ := githubapp.NewSource("7", key, "git@github.com:a/b.git")
	if got := s.RemoteURL(); got != "https://github.com/a/b.git" {
		t.Fatal(got)
	}
	s.API, s.GitBase, s.Now = api.URL, "http://127.0.0.1:9", clock.Now
	if got := s.RemoteURL(); got != "http://127.0.0.1:9/a/b.git" {
		t.Fatal(got)
	}
	env, err := s.GitEnv(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "GIT_CONFIG_KEY_0=http.http://127.0.0.1:9/.extraheader") || !strings.Contains(joined, "http.followRedirects") || !strings.Contains(joined, "Authorization: Basic ") {
		t.Errorf("env %v", env)
	}
	if red := s.Redact(joined); strings.Contains(red, "Basic ") && !strings.Contains(red, "***") {
		t.Errorf("not redacted: %s", red)
	}
}
