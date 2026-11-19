package app

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KazuhaHub/infra-hub/internal/hubca"
	"github.com/KazuhaHub/infra-hub/internal/state"
)

func TestCAInitSignPinCommands(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	code, out, errs := run(t, "ca", "init", "--out", dir, "--permit-ip", "192.0.2.0/24", "--permit-dns", "example.org")
	if code != 0 {
		t.Fatalf("init: %d %s", code, errs)
	}
	pin := strings.TrimSpace(out)
	if !strings.HasPrefix(pin, "sha256//") {
		t.Fatalf("pin %q", pin)
	}
	if code, out, _ := run(t, "ca", "pin", "--cert", filepath.Join(dir, "ca.crt")); code != 0 || strings.TrimSpace(out) != pin {
		t.Errorf("pin: %d %q", code, out)
	}
	if code, _, errs := run(t, "ca", "init", "--out", dir); code != 1 || !strings.Contains(errs, "refusing to overwrite") {
		t.Errorf("second init: %d %q", code, errs)
	}

	// A hub produces a request through `https csr`; the CA signs it; the result verifies against the CA.
	h := newHub(t)
	var cfg map[string]any
	data, _ := os.ReadFile(h.config)
	json.Unmarshal(data, &cfg)
	cfg["httpsAddresses"] = []string{"192.0.2.10", "hub.example.org"}
	data, _ = json.Marshal(cfg)
	os.WriteFile(h.config, data, 0o600)
	code, csr, errs := run(t, "https", "csr", "--config", h.config)
	if code != 0 || !strings.Contains(csr, "BEGIN CERTIFICATE REQUEST") {
		t.Fatalf("https csr: %d %s %s", code, csr, errs)
	}
	if st, err := os.Stat(filepath.Join(h.dir, "hub-https.key")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("hub key: %v", err)
	}
	csrPath, crtPath := filepath.Join(h.dir, "hub.csr"), filepath.Join(h.dir, "hub.crt")
	os.WriteFile(csrPath, []byte(csr), 0o644)
	code, out, errs = run(t, "ca", "sign", "--ca-key", filepath.Join(dir, "ca.key"), "--ca-cert", filepath.Join(dir, "ca.crt"), "--csr", csrPath, "--out", crtPath, "--days", "30")
	if code != 0 || !strings.Contains(out, "serial:") {
		t.Fatalf("sign: %d %s %s", code, out, errs)
	}
	cert, _ := hubca.ReadCertificate(crtPath)
	caCert, _ := hubca.ReadCertificate(filepath.Join(dir, "ca.crt"))
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: "hub.example.org", CurrentTime: fixedNow}); err != nil {
		t.Errorf("signed certificate: %v", err)
	}
	key, _ := hubca.ReadPrivateKey(filepath.Join(h.dir, "hub-https.key"))
	if !cert.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Error("certificate is not for the hub's key")
	}
	// A request for a name outside the CA's constraint is refused.
	k2, _ := hubca.ReadPrivateKey(filepath.Join(h.dir, "hub-https.key"))
	badCSR, _ := hubca.NewCSR(k2, []string{"198.51.100.1"})
	os.WriteFile(csrPath, badCSR, 0o644)
	if code, _, errs := run(t, "ca", "sign", "--ca-key", filepath.Join(dir, "ca.key"), "--ca-cert", filepath.Join(dir, "ca.crt"), "--csr", csrPath, "--out", crtPath+"2"); code != 1 || errs == "" {
		t.Errorf("out-of-constraint sign: %d %q", code, errs)
	}
	// Usage errors exit 2.
	for _, args := range [][]string{{"ca", "init"}, {"ca", "sign"}, {"ca", "pin"}, {"ca", "init", "--out", dir + "x", "--permit-ip", "nope"}, {"ca"}} {
		if code, _, _ := run(t, args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	// https csr without addresses fails.
	if code, _, _ := run(t, "https", "csr", "--config", newHub(t).config); code != 1 {
		t.Errorf("https csr without addresses: %d", code)
	}
}

func TestStatusShowsTheReport(t *testing.T) {
	h := newHub(t)
	h.markMirrored(t)
	st, err := state.LoadState(filepath.Join(h.dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	st.SetReport("h1", state.HostReport{AppliedCommit: "0123456789abcdef0123456789abcdef01234567", Result: "failed", Message: "feature x failed",
		Time: "2026-11-19T08:10:00Z", ReceivedAt: "2026-11-19T08:10:02Z", Features: []state.FeatureSummary{{Name: "x", Result: "failed", Message: "boom"}}})
	if err := st.Flush(); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run(t, "status", "--config", h.config, "--no-refs", "-o", "json")
	if code != 0 {
		t.Fatalf("%d %s", code, errs)
	}
	var doc struct {
		APIVersion string `json:"apiVersion"`
		Hosts      []map[string]any
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	rep, _ := doc.Hosts[0]["report"].(map[string]any)
	if rep["appliedCommit"] != "0123456789abcdef0123456789abcdef01234567" || rep["result"] != "failed" || rep["message"] != "feature x failed" ||
		rep["time"] != "2026-11-19T08:10:00Z" || rep["receivedAt"] != "2026-11-19T08:10:02Z" {
		t.Errorf("report: %v", rep)
	}
	feats, _ := rep["features"].([]any)
	if len(feats) != 1 || feats[0].(map[string]any)["name"] != "x" {
		t.Errorf("features: %v", rep["features"])
	}
	if doc.Hosts[0]["lastSeen"] != "2026-11-19T08:00:00Z" {
		t.Errorf("the host's other fields were lost: %v", doc.Hosts[0])
	}
	// The table mentions it, and a host that never reported has no "report" key.
	if _, table, _ := run(t, "status", "--config", h.config, "--no-refs"); !strings.Contains(table, "failed 0123456789ab") {
		t.Errorf("table:\n%s", table)
	}
	h2 := newHub(t)
	h2.markMirrored(t)
	_, out, _ = run(t, "status", "--config", h2.config, "--no-refs", "-o", "json")
	if strings.Contains(out, `"report"`) {
		t.Errorf("a host without a report shows one:\n%s", out)
	}
	// The legacy document is unchanged by reports.
	_, legacy, _ := run(t, "status", "--config", h.config, "--no-refs", "--format", "legacy")
	if strings.Contains(legacy, "report") || strings.Contains(legacy, "feature x") {
		t.Errorf("legacy status leaks the report:\n%s", legacy)
	}
}
