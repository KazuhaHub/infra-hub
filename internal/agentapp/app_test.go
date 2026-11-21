package agentapp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/KazuhaHub/infra-hub/internal/agent"
	"github.com/KazuhaHub/infra-hub/internal/agenttest"
	"github.com/KazuhaHub/infra-hub/internal/hubkey"
	"github.com/KazuhaHub/infra-hub/internal/sigstorever"
)

// runAgent runs the command line with an empty environment apart from env.
func runAgent(t *testing.T, env map[string]string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	c := &cli{stdout: &out, stderr: &errb, environ: func(k string) (string, bool) { v, ok := env[k]; return v, ok }}
	code = runCLI(c, args)
	return code, out.String(), errb.String()
}

// withLegacy adds the flags that point infra-pull's lock and record into the test's directory.
func withLegacy(w *agenttest.World, args ...string) []string {
	return append(args, "--infra-lock", filepath.Join(w.Dir, "infra", "lock"), "--infra-applied", filepath.Join(w.Dir, "infra-applied"))
}

func writeEnvFile(t *testing.T, w *agenttest.World, mode string, urls, pins []string) string {
	t.Helper()
	old := sigstoreRoot
	sigstoreRoot = func() root.TrustedMaterial { return w.Sigstore.TrustedMaterial() }
	t.Cleanup(func() { sigstoreRoot = old })
	content := "INFRA_AGENT_TOKEN=" + agenttest.Token(t, pins, urls) + "\nINFRA_AGENT_HOST=" + agenttest.Host +
		"\nINFRA_AGENT_AGE_KEY=" + w.AgeKeyPath + "\nINFRA_AGENT_SIGSTORE_REPO_ID=1462297697\nINFRA_AGENT_SIGSTORE_OWNER_ID=165913136\nINFRA_AGENT_STATE_DIR=" + w.StateDir +
		"\nINFRA_AGENT_MODE=" + mode + "\n"
	p := filepath.Join(w.Dir, "agent.env")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunOnceExitCodesAndStatus(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	p := w.Publish(agenttest.Options{})
	envFile := writeEnvFile(t, w, "apply", []string{hub.URL}, []string{hub.Pin})

	code, _, errs := runAgent(t, nil, withLegacy(w, "run", "--once", "--env-file", envFile, "--ansible", w.Stub)...)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if len(w.StubRuns()) != 1 {
		t.Errorf("stub runs %v", w.StubRuns())
	}
	if code, _, errs := runAgent(t, nil, withLegacy(w, "run", "--once", "--env-file", envFile, "--ansible", w.Stub)...); code != 0 {
		t.Fatalf("unchanged: exit %d: %s", code, errs)
	}

	// status -o json: apiVersion v1, camelCase, RFC 3339 times.
	code, out, errs := runAgent(t, nil, "status", "-o", "json", "--env-file", envFile)
	if code != 0 {
		t.Fatalf("status exit %d: %s", code, errs)
	}
	var doc struct {
		APIVersion string `json:"apiVersion"`
		Host       string `json:"host"`
		Mode       string `json:"mode"`
		Applied    struct {
			Commit string `json:"commit"`
			Time   string `json:"time"`
			At     string `json:"at"`
		} `json:"applied"`
		LastResult string `json:"lastResult"`
		LastHub    string `json:"lastHub"`
		LastCycle  string `json:"lastCycle"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if doc.APIVersion != "v1" || doc.Host != "web1" || doc.Mode != "apply" || doc.Applied.Commit != p.Commit || doc.LastResult != "unchanged" || doc.LastHub != hub.URL ||
		!strings.HasSuffix(doc.Applied.Time, "Z") || !strings.HasSuffix(doc.LastCycle, "Z") || strings.Contains(doc.Applied.At, ".") {
		t.Errorf("status %+v\n%s", doc, out)
	}
	if _, table, _ := runAgent(t, nil, "status", "--env-file", envFile); !strings.Contains(table, p.Commit) || !strings.Contains(table, "unchanged") {
		t.Errorf("table:\n%s", table)
	}
	if code, _, _ := runAgent(t, nil, "status", "-o", "yaml", "--env-file", envFile); code != 2 {
		t.Errorf("bad -o: exit %d", code)
	}

	// A failing apply is exit 1.
	w.FailStub(true)
	w.Publish(agenttest.Options{})
	if code, _, errs := runAgent(t, nil, withLegacy(w, "run", "--once", "--env-file", envFile, "--ansible", w.Stub)...); code != 1 || !strings.Contains(errs, "infra-agent: failed:") {
		t.Errorf("failed apply: exit %d, %q", code, errs)
	}

	// A wrong pin is unreachable: exit 1.
	other, _ := hubkey.Generate()
	wrong, _ := hubkey.Pin(other)
	bad := writeEnvFile(t, w, "verify", []string{hub.URL}, []string{wrong})
	if code, _, errs := runAgent(t, nil, withLegacy(w, "run", "--once", "--env-file", bad)...); code != 3 || !strings.Contains(errs, "unreachable") {
		t.Errorf("unreachable: exit %d, %q", code, errs)
	}
}

func TestRunOnceRefusesWhileAnotherAgentRuns(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	w.Publish(agenttest.Options{})
	envFile := writeEnvFile(t, w, "verify", []string{hub.URL}, []string{hub.Pin})
	l, err := agent.AcquireLock(w.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	code, _, errs := runAgent(t, nil, withLegacy(w, "run", "--once", "--env-file", envFile)...)
	if code != 3 || !strings.Contains(errs, "another infra-agent is running") {
		t.Fatalf("exit %d, %q", code, errs)
	}
	l.Close()
	if code, _, errs := runAgent(t, nil, withLegacy(w, "run", "--once", "--env-file", envFile)...); code != 0 {
		t.Fatalf("after the lock is free: exit %d, %q", code, errs)
	}
}

func TestConfigErrorsExitTwo(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(dir, "a.env")
		os.WriteFile(p, []byte(s), 0o600)
		return p
	}
	for name, args := range map[string][]string{
		"missing file":  {"run", "--once", "--env-file", filepath.Join(dir, "none.env")},
		"unknown key":   {"run", "--once", "--env-file", write("INFRA_AGENT_NOPE=1\n")},
		"missing token": {"run", "--once", "--env-file", write("INFRA_AGENT_HOST=web1\n")},
		"check-config":  {"check-config", "--env-file", write("INFRA_AGENT_HOST=web1\n")},
		"status":        {"status", "--env-file", write("")},
		"unknown flag":  {"run", "--nope"},
		"no command":    {},
		"extra arg":     {"version", "x"},
	} {
		code, _, errs := runAgent(t, nil, args...)
		if code != 2 || !strings.HasPrefix(errs, "infra-agent: ") {
			t.Errorf("%s: exit %d, %q", name, code, errs)
		}
	}
	// The environment overrides the file.
	if code, _, errs := runAgent(t, map[string]string{"INFRA_AGENT_MODE": "sideways"}, "status", "--env-file", write("")); code != 2 {
		t.Errorf("env mode: exit %d %q", code, errs)
	}
}

func TestCheckConfig(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	dead := agenttest.DeadURL(t)
	envFile := writeEnvFile(t, w, "verify", []string{dead, hub.URL}, []string{hub.Pin})
	code, out, errs := runAgent(t, nil, "check-config", "--env-file", envFile)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	for _, want := range []string{"host:      web1", "mode:      verify", w.AgeID.Recipient().String(), "hub " + strings.TrimPrefix(hub.URL, "https://") + ": pin matched, status ok", strings.TrimPrefix(dead, "https://")} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "AGE-SECRET-KEY") {
		t.Error("the secret key is printed")
	}
	other, _ := hubkey.Generate()
	wrong, _ := hubkey.Pin(other)
	envFile = writeEnvFile(t, w, "verify", []string{hub.URL}, []string{wrong})
	code, out, errs = runAgent(t, nil, "check-config", "--env-file", envFile)
	if code != 1 || !strings.Contains(out, "does not match any configured pin") {
		t.Errorf("wrong pin: exit %d\n%s\n%s", code, out, errs)
	}
}

func TestCheckConfigSigstore(t *testing.T) {
	old := sigstoreManager
	sigstoreManager = func(cfg agent.Config) *sigstorever.Manager {
		m := cfg.SigstoreManager()
		m.Offline = true
		return m
	}
	defer func() { sigstoreManager = old }()
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	envFile := writeEnvFile(t, w, "verify", []string{hub.URL}, []string{hub.Pin})
	data, _ := os.ReadFile(envFile)
	content := string(data)
	code, out, errs := runAgent(t, nil, "check-config", "--env-file", envFile)
	if code != 0 || !strings.Contains(out, "sigstore:  embedded trusted root ok (") ||
		!strings.Contains(out, "identity https://github.com/KazuhaHub/infra/.github/workflows/attest-main.yml@refs/heads/main") {
		t.Errorf("check-config: exit %d\n%s\n%s", code, out, errs)
	}
	if strings.Contains(out, "signers") || strings.Contains(out, "signature:") {
		t.Errorf("output still mentions the ssh signature:\n%s", out)
	}
	if !strings.Contains(out, "repo ID 1462297697, owner ID 165913136") || !strings.Contains(out, "sigstore root: embedded\n") {
		t.Errorf("IDs and root source:\n%s", out)
	}
	if info, err := sigstorever.ReadInfo(filepath.Join(w.StateDir, "sigstore-root.json")); err != nil || info.Source != sigstorever.SourceEmbedded {
		t.Errorf("info %+v %v", info, err)
	}
	if _, out, _ := runAgent(t, nil, "status", "--env-file", envFile); !strings.Contains(out, "sigstore root  embedded") {
		t.Errorf("status:\n%s", out)
	}
	if _, out, _ := runAgent(t, nil, "status", "-o", "json", "--env-file", envFile); !strings.Contains(out, `"sigstoreRoot"`) {
		t.Errorf("status json:\n%s", out)
	}
	// The IDs are required.
	noIDs := filepath.Join(w.Dir, "noids.env")
	if err := os.WriteFile(noIDs, []byte(strings.Replace(content, "INFRA_AGENT_SIGSTORE_REPO_ID=1462297697\n", "", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := runAgent(t, nil, "check-config", "--env-file", noIDs); code != 2 || !strings.Contains(errs, "SIGSTORE_REPO_ID is required") {
		t.Errorf("missing ID: exit %d %s", code, errs)
	}
	// The retired settings are accepted with a warning, and no allowed_signers file is needed.
	legacy := filepath.Join(w.Dir, "legacy.env")
	if err := os.WriteFile(legacy, []byte(content+"INFRA_AGENT_SIGNATURE=either\nINFRA_AGENT_SIGNERS="+filepath.Join(w.Dir, "none")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errs = runAgent(t, nil, "check-config", "--env-file", legacy)
	if code != 0 || !strings.Contains(errs, "INFRA_AGENT_SIGNATURE=either is deprecated") || !strings.Contains(errs, "INFRA_AGENT_SIGNERS is ignored") {
		t.Errorf("legacy settings: exit %d\n%s", code, errs)
	}
	bad := filepath.Join(w.Dir, "bad.env")
	if err := os.WriteFile(bad, []byte(content+"INFRA_AGENT_SIGNATURE=gpg\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := runAgent(t, nil, "check-config", "--env-file", bad); code != 2 || !strings.Contains(errs, "want sigstore") {
		t.Errorf("bad mode: exit %d %s", code, errs)
	}
}

func TestStatusShowsTheSignature(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	w.Publish(agenttest.Options{})
	envFile := writeEnvFile(t, w, "apply", []string{hub.URL}, []string{hub.Pin})
	if code, _, errs := runAgent(t, nil, withLegacy(w, "run", "--once", "--env-file", envFile, "--ansible", w.Stub)...); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	_, out, _ := runAgent(t, nil, "status", "--env-file", envFile)
	if !strings.Contains(out, ", signature sigstore") {
		t.Errorf("table:\n%s", out)
	}
	_, out, _ = runAgent(t, nil, "status", "-o", "json", "--env-file", envFile)
	if !strings.Contains(out, `"signature": "sigstore"`) {
		t.Errorf("json:\n%s", out)
	}
}

func TestCheckConfigGitHubFallback(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	envFile := writeEnvFile(t, w, "verify", []string{hub.URL}, []string{hub.Pin})
	_, out, _ := runAgent(t, nil, "check-config", "--env-file", envFile)
	if !strings.Contains(out, "github fallback: off") {
		t.Errorf("off:\n%s", out)
	}
	key, hosts := filepath.Join(w.Dir, "deploy_key"), filepath.Join(w.Dir, "github_known_hosts")
	extra := "INFRA_AGENT_GITHUB_REPO=git@github.com:KazuhaHub/infra.git\nINFRA_AGENT_GITHUB_KEY=" + key + "\nINFRA_AGENT_GITHUB_KNOWN_HOSTS=" + hosts + "\n"
	data, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(envFile, append(data, extra...), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := runAgent(t, nil, "check-config", "--env-file", envFile); code != 2 || !strings.Contains(errs, "GitHub deploy key") {
		t.Errorf("missing key: exit %d: %s", code, errs)
	}
	for _, f := range []string{key, hosts} {
		if err := os.WriteFile(f, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	code, out, errs := runAgent(t, nil, "check-config", "--env-file", envFile)
	if code != 0 || !strings.Contains(out, "github fallback: on (repo git@github.com:KazuhaHub/infra.git") {
		t.Errorf("on: exit %d\n%s\n%s", code, out, errs)
	}
}

func TestVersion(t *testing.T) {
	code, out, _ := runAgent(t, nil, "version")
	if code != 0 || !strings.HasPrefix(out, "infra-agent ") {
		t.Errorf("%d %q", code, out)
	}
	code, out, _ = runAgent(t, nil, "--version")
	if code != 0 || !strings.HasPrefix(out, "infra-agent ") {
		t.Errorf("%d %q", code, out)
	}
}

func TestLogSettingsFromTheEnvFile(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	w.Publish(agenttest.Options{})
	envFile := writeEnvFile(t, w, "verify", []string{hub.URL}, []string{hub.Pin})
	f, _ := os.OpenFile(envFile, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("INFRA_AGENT_LOG_FORMAT=json\n")
	f.Close()
	code, _, errs := runAgent(t, nil, withLegacy(w, "run", "--once", "--env-file", envFile)...)
	if code != 0 || !strings.Contains(errs, `"msg":"cycle finished"`) {
		t.Fatalf("exit %d, log:\n%s", code, errs)
	}
}

func TestTestOnlyFlagsCannotComeFromTheEnvironment(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	w.Publish(agenttest.Options{})
	envFile := writeEnvFile(t, w, "verify", []string{hub.URL}, []string{hub.Pin})
	// If INFRA_AGENT_REPO took effect the bundle (statement repo KazuhaHub/infra) would be rejected.
	env := map[string]string{"INFRA_AGENT_REPO": "Evil/infra", "INFRA_AGENT_ANSIBLE": "/bin/false", "INFRA_AGENT_SSH_KEYGEN": "/bin/false",
		"INFRA_AGENT_INFRA_LOCK": "/nonexistent/lock", "INFRA_AGENT_INFRA_APPLIED": "/nonexistent/applied"}
	code, _, errs := runAgent(t, env, withLegacy(w, "run", "--once", "--env-file", envFile)...)
	if code != 0 || strings.Contains(errs, "flag=--ansible") || strings.Contains(errs, "flag=--repo") || strings.Contains(errs, "flag=--ssh-keygen") {
		t.Fatalf("exit %d: %s", code, errs)
	}
	// Nor from agent.env: an unknown setting.
	bad := filepath.Join(w.Dir, "bad.env")
	os.WriteFile(bad, []byte("INFRA_AGENT_REPO=Evil/infra\n"), 0o600)
	if code, _, errs := runAgent(t, nil, "status", "--env-file", bad); code != 2 || !strings.Contains(errs, "unknown setting INFRA_AGENT_REPO") {
		t.Errorf("exit %d %q", code, errs)
	}
	// On the command line they work, and the agent says so at startup.
	_, _, errs = runAgent(t, nil, withLegacy(w, "run", "--once", "--env-file", envFile, "--ansible", w.Stub)...)
	for _, f := range []string{`flag=--ansible`, `flag=--infra-lock`, `flag=--infra-applied`} {
		if !strings.Contains(errs, f) || !strings.Contains(errs, "test-only flag is set") {
			t.Errorf("no warning for %s:\n%s", f, errs)
		}
	}
	if strings.Contains(errs, "flag=--repo") {
		t.Errorf("a warning for a flag at its default:\n%s", errs)
	}
}

func TestConfigurationErrorsFromTheFilesExitTwo(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	w.Publish(agenttest.Options{})
	envFile := writeEnvFile(t, w, "verify", []string{hub.URL}, []string{hub.Pin})
	os.WriteFile(filepath.Join(w.Dir, "infra-applied"), []byte("broken"), 0o644)
	code, _, errs := runAgent(t, nil, withLegacy(w, "run", "--once", "--env-file", envFile)...)
	if code != 1 || !strings.Contains(errs, "malformed") { // a failed cycle, never a crash
		t.Errorf("malformed applied record: exit %d %q", code, errs)
	}
	os.WriteFile(filepath.Join(w.Dir, "infra-applied"), []byte(strings.Repeat("a", 40)+" 0\n"), 0o644)
	if code, _, errs = runAgent(t, nil, withLegacy(w, "run", "--once", "--env-file", envFile)...); code != 0 {
		t.Errorf("applied_at 0: exit %d %q", code, errs)
	}
	os.Remove(filepath.Join(w.Dir, "infra-applied"))
	os.MkdirAll(w.StateDir, 0o755)
	os.Chmod(w.StateDir, 0o755)
	code, _, errs = runAgent(t, nil, withLegacy(w, "run", "--once", "--env-file", envFile)...)
	if code != 2 || !strings.Contains(errs, "must be 0700") {
		t.Errorf("state dir: exit %d %q", code, errs)
	}
}

func TestRunOnceInterruptedBySignalExitsThree(t *testing.T) {
	w := agenttest.NewWorld(t)
	hub := w.StartHub()
	w.Publish(agenttest.Options{})
	envFile := writeEnvFile(t, w, "apply", []string{hub.URL}, []string{hub.Pin})
	slow := filepath.Join(w.Dir, "slow")
	os.WriteFile(slow, []byte("#!/bin/sh\nexec sleep 30\n"), 0o755)
	go func() {
		time.Sleep(1500 * time.Millisecond) // the cycle is inside ansible by then
		syscall.Kill(os.Getpid(), syscall.SIGTERM)
	}()
	code, _, errs := runAgent(t, nil, withLegacy(w, "run", "--once", "--env-file", envFile, "--ansible", slow)...)
	if code != 3 || !strings.Contains(errs, "interrupted") {
		t.Fatalf("exit %d: %s", code, errs)
	}
}
