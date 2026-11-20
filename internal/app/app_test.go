package app

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/config"
	"github.com/KazuhaHub/infra-hub/internal/iplists"
	"github.com/KazuhaHub/infra-hub/internal/logx"
	"github.com/KazuhaHub/infra-hub/internal/version"
	legolog "github.com/go-acme/lego/v4/log"
)

// hubDir is a config file and the state it points at.
type hubDir struct {
	dir, config string
}

// newHub writes a config for one client host "h1" and one IP list "edge" (provider "cdn", never fetched).
func newHub(t *testing.T) hubDir {
	t.Helper()
	dir := t.TempDir()
	cfg := map[string]any{
		"repo": filepath.Join(dir, "infra.git"), "upstream": "git@example.invalid:x/infra.git",
		"httpsAddresses": []string{"127.0.0.1"}, "https": map[string]any{"listen": "127.0.0.1:18443", "key": filepath.Join(dir, "hub.key")},
		"clients":   map[string]any{"h1": map[string]any{}},
		"ipSources": map[string]any{"cdn": map[string]any{"url": "https://example.invalid/ips", "format": "lines"}},
		"ipLists":   map[string]any{"edge": map[string]any{"providers": []string{"cdn"}}},
	}
	data, _ := json.Marshal(cfg)
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return hubDir{dir: dir, config: path}
}

// markMirrored records a successful mirror fetch 90 seconds before the fixed test clock.
func (h hubDir) markMirrored(t *testing.T) {
	t.Helper()
	data := `{"mirror_last_success":"` + fixedNow.Add(-90*time.Second).Format(time.RFC3339) + `"}`
	if err := os.WriteFile(filepath.Join(h.dir, "state.json"), []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

var fixedNow = time.Date(2026, 11, 19, 8, 20, 33, 0, time.UTC)

// run executes the command line as the process would and returns the exit code and both streams.
func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	var out, errb bytes.Buffer
	c := &cli{stdout: &out, stderr: &errb, now: func() time.Time { return fixedNow }}
	return runCLI(c, args), out.String(), errb.String()
}

func TestVersion(t *testing.T) {
	version.Version, version.Commit, version.Date = "0.2.0", "abcdef0", "2026-11-19"
	t.Cleanup(func() { version.Version, version.Commit, version.Date = "dev", "unknown", "unknown" })
	const want = "infra-hub 0.2.0 (commit abcdef0, built 2026-11-19)\n"
	for _, args := range [][]string{{"version"}, {"--version"}, {"-v"}} {
		code, out, _ := run(t, args...)
		if code != 0 || out != want {
			t.Errorf("%v: code %d, output %q", args, code, out)
		}
	}
}

func TestExitCodes(t *testing.T) {
	h := newHub(t)
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"no command", nil, ExitUsage},
		{"unknown command", []string{"bogus"}, ExitUsage},
		{"unknown flag", []string{"status", "--nope"}, ExitUsage},
		{"extra argument", []string{"status", "x"}, ExitUsage},
		{"missing argument", []string{"iplist", "accept"}, ExitUsage},
		{"iplist alone", []string{"iplist"}, ExitUsage},
		{"bad output", []string{"status", "--config", h.config, "-o", "yaml"}, ExitUsage},
		{"bad log level", []string{"--log-level", "loud", "version"}, ExitUsage},
		{"bad log format", []string{"--log-format", "xml", "version"}, ExitUsage},
		{"negative limit", []string{"iplist", "history", "edge", "--config", h.config, "--limit", "-1"}, ExitUsage},
		{"missing config file", []string{"status", "--config", filepath.Join(h.dir, "none.json")}, ExitFailed},
		{"unknown list", []string{"iplist", "history", "nope", "--config", h.config}, ExitFailed},
		{"nothing held", []string{"iplist", "accept", "cdn", "--config", h.config}, ExitFailed},
		{"not ready", []string{"status", "--config", h.config, "--no-refs", "-o", "json"}, ExitNotReady},
		{"help", []string{"--help"}, ExitOK},
	}
	for _, tc := range cases {
		if code, _, errs := run(t, tc.args...); code != tc.want {
			t.Errorf("%s: exit %d, want %d (stderr %q)", tc.name, code, tc.want, errs)
		}
	}
	h.markMirrored(t)
	if code, _, errs := run(t, "status", "--config", h.config, "--no-refs", "-o", "json"); code != ExitOK {
		t.Errorf("ready: exit %d (stderr %q)", code, errs)
	}
}

func TestErrorsAreOneLineOnStderr(t *testing.T) {
	code, out, errs := run(t, "status", "--config", "/nonexistent/config.json")
	if code != ExitFailed || out != "" {
		t.Fatalf("code %d, stdout %q", code, out)
	}
	if !strings.HasPrefix(errs, "infra-hub: load config /nonexistent/config.json: ") || strings.Count(errs, "\n") != 1 {
		t.Errorf("stderr %q", errs)
	}
}

func TestEnvironmentSuppliesFlags(t *testing.T) {
	h := newHub(t)
	h.markMirrored(t)
	t.Setenv("INFRA_HUB_CONFIG", h.config)
	t.Setenv("INFRA_HUB_OUTPUT", "json")
	t.Setenv("INFRA_HUB_NO_REFS", "true")
	code, out, errs := run(t, "status")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil || doc["apiVersion"] != "v1" {
		t.Fatalf("not the v1 document: %v %q", err, out)
	}
	// a flag on the command line wins over the environment
	if _, out, _ := run(t, "status", "-o", "table"); strings.HasPrefix(out, "{") {
		t.Errorf("the flag did not win: %q", out)
	}
	t.Setenv("INFRA_HUB_OUTPUT", "")
	t.Setenv("INFRA_HUB_LIMIT", "many")
	if code, _, errs := run(t, "iplist", "history", "edge"); code != ExitUsage || !strings.Contains(errs, "INFRA_HUB_LIMIT") {
		t.Errorf("bad environment value: exit %d, %q", code, errs)
	}
}

func TestIPListHistoryAndAccept(t *testing.T) {
	h := newHub(t)
	h.markMirrored(t)
	if err := iplists.AppendHistory(h.dirIPLists(t), "edge", iplists.HistoryEntry{Time: "2026-11-19T08:00:00Z", Event: "first fetch", Provider: "cdn", CountAfter: 2}); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run(t, "iplist", "history", "edge", "--config", h.config, "--limit", "1")
	if code != ExitOK || errs != "" {
		t.Fatalf("iplist history: exit %d, stderr %q", code, errs)
	}
	if !strings.Contains(out, `"countAfter": 2`) || !strings.Contains(out, `"apiVersion": "v1"`) {
		t.Errorf("iplist history output: %s", out)
	}
	if _, out, _ := run(t, "iplist", "history", "edge", "--config", h.config, "-o", "table"); !strings.Contains(out, "first fetch") {
		t.Errorf("table: %q", out)
	}
	code, _, errs = run(t, "iplist", "accept", "--config", h.config, "cdn")
	if code != ExitFailed || !strings.Contains(errs, "has no held update") {
		t.Errorf("iplist accept: exit %d, stderr %q", code, errs)
	}
}

// The spellings of the first releases are gone: they are usage errors, not aliases.
func TestRemovedSpellingsAreRefused(t *testing.T) {
	h := newHub(t)
	h.markMirrored(t)
	for _, args := range [][]string{
		{"status", "-config", h.config, "-no-refs"},
		{"iplist-accept", "--config", h.config, "cdn"},
		{"iplist-history", "--config", h.config, "edge"},
		{"status", "--config", h.config, "--no-refs", "--format", "legacy"},
	} {
		if code, _, _ := run(t, args...); code != ExitUsage {
			t.Errorf("%v: exit %d, want %d", args, code, ExitUsage)
		}
	}
	if code, _, errs := run(t, "status", "--config", h.config, "--no-refs", "-o", "json"); code != ExitOK || errs != "" {
		t.Errorf("status: exit %d, %q", code, errs)
	}
}

func (h hubDir) dirIPLists(t *testing.T) string {
	t.Helper()
	cfg, err := config.LoadConfig(h.config)
	if err != nil {
		t.Fatal(err)
	}
	return cfg.IPListDir
}

func TestStatusWithNoRefsRunsNoGit(t *testing.T) {
	bin := t.TempDir()
	marker := filepath.Join(bin, "git-ran")
	os.WriteFile(filepath.Join(bin, "git"), []byte("#!/bin/sh\ntouch "+marker+"\necho 'abc refs/heads/main'\n"), 0o755)
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	cfg := config.Config{Repo: "/x/infra.git", State: filepath.Join(t.TempDir(), "s.json"), Clients: map[string]config.Client{"h": {}}, CertDir: t.TempDir()}
	if _, err := collectStatus(context.Background(), cfg, true, fixedNow); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("git ran with no-refs")
	}
	in, err := collectStatus(context.Background(), cfg, false, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("git did not run without no-refs")
	}
	if in.Main != "abc" {
		t.Errorf("main %q", in.Main)
	}
}

// lego logs through its own logger; after setup it must land in the same stream, in the same format, redacted.
func TestLegoLogGoesThroughTheLogger(t *testing.T) {
	t.Cleanup(logx.ResetSecrets)
	prevLego := legolog.Logger
	t.Cleanup(func() { legolog.Logger = prevLego })
	const token = "cf-token-for-lego-0123456789"
	logx.AddSecret(token)
	for _, format := range []string{"text", "json"} {
		var out, errb bytes.Buffer
		c := &cli{stdout: &out, stderr: &errb, now: func() time.Time { return fixedNow }}
		prev := slog.Default()
		if code := runCLI(c, []string{"--log-format", format, "--log-level", "debug", "version"}); code != 0 {
			t.Fatalf("exit %d", code)
		}
		legolog.Infof("[a.example.org] presenting with %s", token)
		legolog.Warnf("[a.example.org] retry")
		slog.SetDefault(prev)
		got := errb.String()
		if strings.Contains(got, token) || !strings.Contains(got, "[redacted]") || !strings.Contains(got, "retry") {
			t.Errorf("%s: lego output not captured and redacted:\n%s", format, got)
		}
		if format == "json" && !strings.HasPrefix(got, "{") {
			t.Errorf("lego output is not JSON: %s", got)
		}
	}
}
