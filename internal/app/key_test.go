package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KazuhaHub/infra-hub/internal/jointoken"
)

func TestKeyInitAndPin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.key")
	code, out, errs := run(t, "key", "init", "--out", path)
	if code != 0 {
		t.Fatalf("init: %d %s", code, errs)
	}
	pin := strings.TrimSpace(out)
	if !strings.HasPrefix(pin, "sha256//") {
		t.Fatalf("pin %q", pin)
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("key file: %v", err)
	}
	if strings.Contains(out+errs, "PRIVATE KEY") {
		t.Error("the key was printed")
	}
	if code, out, _ := run(t, "key", "pin", "--key", path); code != 0 || strings.TrimSpace(out) != pin {
		t.Errorf("pin: %d %q", code, out)
	}
	code, out, _ = run(t, "key", "pin", "--key", path, "-o", "json")
	var doc map[string]string
	if err := json.Unmarshal([]byte(out), &doc); err != nil || code != 0 || doc["apiVersion"] != "v1" || doc["pin"] != pin {
		t.Errorf("pin json: %d %q", code, out)
	}
	before, _ := os.ReadFile(path)
	if code, _, errs := run(t, "key", "init", "--out", path); code != 1 || !strings.Contains(errs, "refusing to overwrite") {
		t.Errorf("second init: %d %q", code, errs)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Error("the key was overwritten")
	}
	code, out, _ = run(t, "key", "init", "--out", filepath.Join(t.TempDir(), "k2"), "-o", "json")
	doc = nil
	if err := json.Unmarshal([]byte(out), &doc); err != nil || code != 0 || doc["apiVersion"] != "v1" || !strings.HasPrefix(doc["pin"], "sha256//") || doc["path"] == "" {
		t.Errorf("init json: %d %q", code, out)
	}
	// A garbage file and a loose file are failures, not usage errors.
	bad := filepath.Join(t.TempDir(), "bad")
	os.WriteFile(bad, []byte("nope"), 0o600)
	if code, _, errs := run(t, "key", "pin", "--key", bad); code != 1 || errs == "" {
		t.Errorf("garbage: %d %q", code, errs)
	}
	for _, args := range [][]string{{"key"}, {"key", "init"}, {"key", "pin"}, {"key", "pin", "--key", path, "-o", "xml"}, {"token"}, {"token", "--key", path}, {"token", "--hub", "https://h:1"},
		{"token", "--key", path, "--hub", "http://h:1"}, {"ca"}, {"https", "csr"}} {
		if code, _, _ := run(t, args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}

func TestToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.key")
	_, out, _ := run(t, "key", "init", "--out", path)
	pin := strings.TrimSpace(out)
	code, out, errs := run(t, "token", "--key", path, "--hub", "https://192.0.2.10:8443", "--hub", "https://hub.example.org:8443/")
	if code != 0 || strings.Count(out, "\n") != 1 || strings.Contains(errs, "PRIVATE") {
		t.Fatalf("token: %d %q %q", code, out, errs)
	}
	tok, err := jointoken.Decode(strings.TrimSpace(out))
	if err != nil || len(tok.Pins) != 1 || tok.Pins[0] != pin || len(tok.Hubs) != 2 || tok.Hubs[1] != "https://hub.example.org:8443" {
		t.Errorf("decoded: %+v %v", tok, err)
	}
	code, out2, _ := run(t, "token", "--key", path, "--hub", "https://192.0.2.10:8443", "-o", "json")
	var doc struct {
		APIVersion string   `json:"apiVersion"`
		Token      string   `json:"token"`
		Pins       []string `json:"pins"`
		Hubs       []string `json:"hubs"`
	}
	if err := json.Unmarshal([]byte(out2), &doc); err != nil || code != 0 || doc.APIVersion != "v1" || doc.Pins[0] != pin || doc.Hubs[0] != "https://192.0.2.10:8443" {
		t.Fatalf("json: %d %q", code, out2)
	}
	if _, err := jointoken.Decode(doc.Token); err != nil {
		t.Error(err)
	}
}

func TestTokenFromPins(t *testing.T) {
	dir := t.TempDir()
	_, out, _ := run(t, "key", "init", "--out", filepath.Join(dir, "a.key"))
	pinA := strings.TrimSpace(out)
	_, out, _ = run(t, "key", "init", "--out", filepath.Join(dir, "b.key"))
	pinB := strings.TrimSpace(out)
	decode := func(args ...string) jointoken.Token {
		t.Helper()
		code, out, errs := run(t, append([]string{"token", "--hub", "https://h.example.org:8443"}, args...)...)
		if code != 0 {
			t.Fatalf("%v: %d %s", args, code, errs)
		}
		tok, err := jointoken.Decode(strings.TrimSpace(out))
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	// Pins only: no key file is read. Order as given, repeats listed once.
	if tok := decode("--pin", pinB, "--pin", pinA, "--pin", pinB); len(tok.Pins) != 2 || tok.Pins[0] != pinB || tok.Pins[1] != pinA {
		t.Errorf("pins: %v", tok.Pins)
	}
	// Both together: the key's pin first, then the given ones, deduplicated.
	if tok := decode("--key", filepath.Join(dir, "a.key"), "--pin", pinB, "--pin", pinA); len(tok.Pins) != 2 || tok.Pins[0] != pinA || tok.Pins[1] != pinB {
		t.Errorf("key and pins: %v", tok.Pins)
	}
	for _, args := range [][]string{{"token", "--hub", "https://h:1"}, {"token", "--pin", "nope", "--hub", "https://h:1"}, {"token", "--pin", pinA},
		{"token", "--pin", pinA, "--hub", "https://h:1", "--hub", "https://h:1/"}} {
		if code, _, _ := run(t, args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}

func TestOldConfigFieldsAreIgnored(t *testing.T) {
	h := newHub(t)
	h.markMirrored(t)
	var cfg map[string]any
	data, _ := os.ReadFile(h.config)
	json.Unmarshal(data, &cfg)
	cfg["httpsAddresses"] = []string{"192.0.2.10"}
	cfg["https"] = map[string]any{"listen": "192.0.2.10:8443", "caCert": "/etc/infra-hub/ca.crt", "cert": "/etc/infra-hub/hub.crt"}
	data, _ = json.Marshal(cfg)
	os.WriteFile(h.config, data, 0o600)
	code, _, errs := run(t, "status", "--config", h.config, "--no-refs")
	if code != 0 || !strings.Contains(errs, "https.key") || !strings.Contains(errs, "https is off") {
		t.Errorf("old config: %d %q", code, errs)
	}
}
