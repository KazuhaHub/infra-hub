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
	"github.com/KazuhaHub/infra-hub/internal/testutil"
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
	_, key := testutil.NewKey(t)
	cfg := map[string]any{
		"listen": "127.0.0.1:11882", "repo": filepath.Join(dir, "infra.git"), "upstream": "git@example.invalid:x/infra.git",
		"host_key": filepath.Join(dir, "host_key"), "clients": map[string]string{"h1": key},
		"ip_sources": map[string]any{"cdn": map[string]any{"url": "https://example.invalid/ips", "format": "lines"}},
		"ip_lists":   map[string]any{"edge": map[string]any{"providers": []string{"cdn"}, "hosts": []string{"h1"}}},
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
	data := `{"mirror_last_success":"` + fixedNow.Add(-90*time.Second).Format(time.RFC3339) + `","hosts":{"h1":{"last_seen":"2026-11-19T08:00:00Z","main":"abc"}}}`
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

func TestOldSpellingsStillWork(t *testing.T) {
	h := newHub(t)
	h.markMirrored(t)

	// -config and -no-refs, with a warning each
	code, out, errs := run(t, "status", "-config", h.config, "-no-refs")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	for _, flag := range []string{"-config", "-no-refs"} {
		if !strings.Contains(errs, "warning: "+flag+" is deprecated") {
			t.Errorf("no deprecation warning for %s: %q", flag, errs)
		}
	}
	var legacy map[string]any
	if err := json.Unmarshal([]byte(out), &legacy); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"mirror_last_success", "mirror_age_seconds", "main_attestation", "hosts", "certs", "issuer", "time"} {
		if _, ok := legacy[k]; !ok {
			t.Errorf("legacy status lacks %q", k)
		}
	}
	if _, ok := legacy["apiVersion"]; ok {
		t.Error("legacy status carries apiVersion")
	}
	if _, ok := legacy["hosts"].(map[string]any)["h1"]; !ok {
		t.Error("legacy hosts is not a map keyed by name")
	}

	// -config=<file> form; an explicit -o asks for the new document even with the old spelling
	_, out, _ = run(t, "status", "-config="+h.config, "--no-refs", "-o", "json")
	if !strings.Contains(out, `"apiVersion": "v1"`) {
		t.Errorf("-o json with -config did not give v1: %q", out)
	}
	// the new spelling gives the new document by default only with -o json; --format legacy is the hidden way back
	_, out, _ = run(t, "status", "--config", h.config, "--no-refs", "--format", "legacy")
	if !strings.Contains(out, `"mirror_age_seconds"`) {
		t.Errorf("--format legacy: %q", out)
	}
	if code, _, _ := run(t, "status", "--config", h.config, "--no-refs", "--format", "v2"); code != ExitUsage {
		t.Errorf("unknown format: exit %d", code)
	}

	// iplist-history: old name, old JSON
	if err := iplists.AppendHistory(h.dirIPLists(t), "edge", iplists.HistoryEntry{Time: "2026-11-19T08:00:00Z", Event: "first fetch", Provider: "cdn", CountAfter: 2}); err != nil {
		t.Fatal(err)
	}
	code, out, errs = run(t, "iplist-history", "-config", h.config, "edge", "-limit", "1")
	if code != ExitOK || !strings.Contains(errs, "iplist-history is deprecated") || !strings.Contains(errs, "-limit is deprecated") {
		t.Fatalf("iplist-history: exit %d, stderr %q", code, errs)
	}
	if !strings.Contains(out, `"count_after": 2`) || strings.Contains(out, "apiVersion") {
		t.Errorf("iplist-history output is not the old JSON: %s", out)
	}
	// iplist history: new name, new JSON
	code, out, errs = run(t, "iplist", "history", "edge", "--config", h.config, "--limit", "1")
	if code != ExitOK || errs != "" {
		t.Fatalf("iplist history: exit %d, stderr %q", code, errs)
	}
	if !strings.Contains(out, `"countAfter": 2`) || !strings.Contains(out, `"apiVersion": "v1"`) {
		t.Errorf("iplist history output: %s", out)
	}
	if _, out, _ := run(t, "iplist", "history", "edge", "--config", h.config, "-o", "table"); !strings.Contains(out, "first fetch") {
		t.Errorf("table: %q", out)
	}

	// iplist-accept: old name, warns, and fails the same way as the new one when nothing is held
	code, _, errs = run(t, "iplist-accept", "-config", h.config, "cdn")
	if code != ExitFailed || !strings.Contains(errs, "iplist-accept is deprecated") || !strings.Contains(errs, "has no held update") {
		t.Errorf("iplist-accept: exit %d, stderr %q", code, errs)
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

func TestHiddenAliasesAreNotListedInHelp(t *testing.T) {
	_, out, _ := run(t, "--help")
	for _, hidden := range []string{"iplist-accept", "iplist-history"} {
		if strings.Contains(out, hidden) {
			t.Errorf("help lists %s", hidden)
		}
	}
	_, out, _ = run(t, "status", "--help")
	if strings.Contains(out, "--format") {
		t.Error("status help lists --format")
	}
}

func TestRewriteLegacyFlags(t *testing.T) {
	out, warns, legacyConfig := rewriteLegacyFlags([]string{"status", "-config", "c.json", "-no-refs", "-config=d", "--", "-config"})
	if got := strings.Join(out, " "); got != "status --config c.json --no-refs --config=d -- -config" {
		t.Errorf("rewritten: %q", got)
	}
	if len(warns) != 2 || !legacyConfig {
		t.Errorf("warnings %v, legacyConfig %v", warns, legacyConfig)
	}
	out, warns, legacyConfig = rewriteLegacyFlags([]string{"status", "--config", "c.json", "-o", "json"})
	if strings.Join(out, " ") != "status --config c.json -o json" || len(warns) != 0 || legacyConfig {
		t.Errorf("new spelling touched: %v %v %v", out, warns, legacyConfig)
	}
}

func TestStatusWithNoRefsRunsNoGit(t *testing.T) {
	bin := t.TempDir()
	marker := filepath.Join(bin, "git-ran")
	os.WriteFile(filepath.Join(bin, "git"), []byte("#!/bin/sh\ntouch "+marker+"\necho 'abc refs/heads/main'\n"), 0o755)
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	cfg := config.Config{Repo: "/x/infra.git", State: filepath.Join(t.TempDir(), "s.json"), Clients: map[string]string{"h": ""}, CertDir: t.TempDir()}
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

func TestStatusWarningNamesTheReplacementThatKeepsScriptsWorking(t *testing.T) {
	_, warns, _ := rewriteLegacyFlags([]string{"status", "-config", "c.json", "-no-refs"})
	if len(warns) < 1 || !strings.Contains(warns[0], "--config <file> -o json") || !strings.Contains(warns[0], "--format legacy") ||
		!strings.Contains(warns[0], "JSON keys change") || !strings.Contains(warns[0], migrationNote) {
		t.Errorf("status warning: %v", warns)
	}
	_, warns, _ = rewriteLegacyFlags([]string{"iplist-history", "-config", "c.json", "edge"})
	if len(warns) != 1 || strings.Contains(warns[0], "-o json") {
		t.Errorf("other commands get the plain advice: %v", warns)
	}
}

// Only flags on the command line choose the old default; the environment does not.
func TestLegacyDefaultIgnoresTheEnvironment(t *testing.T) {
	h := newHub(t)
	h.markMirrored(t)
	t.Setenv("INFRA_HUB_OUTPUT", "json")
	_, out, _ := run(t, "status", "-config", h.config, "--no-refs")
	if !strings.Contains(out, `"mirror_age_seconds"`) {
		t.Errorf("INFRA_HUB_OUTPUT switched the old default away: %s", out)
	}
}
