package app

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCheck(t *testing.T, config string) (code int, stdout, stderr string) {
	t.Helper()
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	var out, errb bytes.Buffer
	code = Main([]string{"check-config", "--config", config}, &out, &errb)
	return code, out.String(), errb.String()
}

// The key in newHub's config does not exist: check-config must not open it.
func TestCheckConfigPasses(t *testing.T) {
	h := newHub(t)
	code, out, errs := runCheck(t, h.config)
	if code != 0 {
		t.Fatalf("code %d: %s", code, errs)
	}
	if !strings.Contains(out, "config ok: https 127.0.0.1:18443, 1 clients, 0 certs, 1 ip lists") {
		t.Errorf("stdout %q", out)
	}
	if _, err := os.Stat(filepath.Join(h.dir, "state.json")); err == nil {
		t.Error("check-config wrote the state file")
	}
}

func TestCheckConfigOldSSHKeysWarn(t *testing.T) {
	h := newHub(t)
	var m map[string]any
	data, _ := os.ReadFile(h.config)
	json.Unmarshal(data, &m)
	m["listen"] = "127.0.0.1:2222"
	m["hostKey"] = filepath.Join(h.dir, "host_key")
	m["clients"] = map[string]any{"h1": map[string]any{"sshKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dB4w4rTZe"}}
	data, _ = json.Marshal(m)
	os.WriteFile(h.config, data, 0o600)
	code, _, errs := runCheck(t, h.config)
	if code != 0 {
		t.Fatalf("code %d: %s", code, errs)
	}
	if !strings.Contains(errs, "removed SSH server") {
		t.Errorf("no warning on stderr: %q", errs)
	}
}

func TestCheckConfigInvalid(t *testing.T) {
	h := newHub(t)
	if err := os.WriteFile(h.config, []byte(`{"repo": "x", "certs": {"a.example.org": "nobody"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := runCheck(t, h.config)
	if code != 1 || out != "" || errs == "" {
		t.Errorf("code %d stdout %q stderr %q", code, out, errs)
	}
	if code, _, _ := runCheck(t, filepath.Join(h.dir, "missing.json")); code != 1 {
		t.Errorf("missing config: code %d", code)
	}
}

func TestCheckConfigState(t *testing.T) {
	h := newHub(t)
	state := filepath.Join(h.dir, "state.json")
	if code, _, errs := runCheck(t, h.config); code != 0 {
		t.Fatalf("no state file: code %d: %s", code, errs)
	}
	if err := os.WriteFile(state, []byte(`{"reports": {}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := runCheck(t, h.config); code != 0 {
		t.Fatalf("good state file: code %d: %s", code, errs)
	}
	if err := os.WriteFile(state, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errs := runCheck(t, h.config)
	if code != 1 || !strings.Contains(errs, "state") {
		t.Errorf("garbage state: code %d: %s", code, errs)
	}
	os.Remove(state)
	os.Mkdir(state, 0o700) // unreadable as a file
	if code, _, _ := runCheck(t, h.config); code != 1 {
		t.Errorf("state is a directory: code %d", code)
	}
}
