package app

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/certs"
	"github.com/KazuhaHub/infra-hub/internal/config"
	"github.com/KazuhaHub/infra-hub/internal/iplists"
	"github.com/KazuhaHub/infra-hub/internal/report"
)

// testdata/status-legacy-origin-main.json is the legacy (snake_case) status for the state tree that writeLegacyFixture
// creates. It began as the output of the binary built from origin/main (commit f9fdeeb) for
// `infra-hub status -config <dir>/config.json -no-refs`, with "time" replaced by 2026-11-19T08:20:33Z and
// "mirror_age_seconds" by 95 (the mirror success is 95 s before that time). Since v0.10.0 it was edited by hand: a
// host's last_seen is the time of its latest report (the SSH server that fed it is gone), the per-host main and
// main_attestation are gone, and the lists have no "hosts".
var fixtureDir = flag.String("fixture-dir", "", "write the legacy status fixture tree here and stop")

func TestWriteLegacyFixture(t *testing.T) {
	if *fixtureDir == "" {
		t.Skip("only used to regenerate testdata/status-legacy-origin-main.json")
	}
	writeLegacyFixture(t, *fixtureDir)
}

// writeLegacyFixture creates a hub config and its state tree: two clients (one never seen), two certificates (one
// stored, one failing), one held IP provider with a list and a history entry. Every time is fixed, and the IP
// provider's last success is far in the future so that no "stale" warning depends on the clock.
func writeLegacyFixture(t *testing.T, dir string) string {
	t.Helper()
	cfgData, _ := json.Marshal(map[string]any{
		"repo": filepath.Join(dir, "infra.git"), "upstream": "git@example.invalid:x/infra.git",
		"httpsAddresses": []string{"127.0.0.1"}, "https": map[string]any{"listen": "127.0.0.1:18443", "key": filepath.Join(dir, "hub.key")},
		"clients":   map[string]any{"h1": map[string]any{}, "h2": map[string]any{}},
		"certs":     map[string]string{"a.example.org": "h1", "b.example.org": "h2"},
		"ipSources": map[string]any{"cdn": map[string]any{"url": "https://example.invalid/ips", "format": "lines"}},
		"ipLists":   map[string]any{"edge": map[string]any{"providers": []string{"cdn"}, "manual": []string{"8.8.8.0/24"}}},
	})
	cfgPath := filepath.Join(dir, "config.json")
	must(t, os.MkdirAll(dir, 0o700))
	must(t, os.WriteFile(cfgPath, cfgData, 0o600))
	must(t, os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{
  "mirror_last_success": "2026-11-19T08:18:58Z",
  "reports": {"h2": {"result": "ok", "time": "2026-11-19T08:17:30Z", "receivedAt": "2026-11-19T08:17:33Z"}}
}
`), 0o644))
	store := certs.CertStore{Dir: filepath.Join(dir, "certs")}
	bundle, _ := makeBundleUntil(t, "b.example.org", time.Date(2027, 1, 17, 0, 0, 0, 0, time.UTC))
	must(t, store.SaveBundle("b.example.org", bundle))
	must(t, store.SaveRecord("b.example.org", certs.CertRecord{LastAttempt: time.Date(2026, 11, 18, 3, 0, 0, 0, time.UTC), LastResult: "ok"}))
	must(t, store.SaveRecord("a.example.org", certs.CertRecord{LastAttempt: time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC), LastResult: "error", LastError: "dns timeout",
		Failures: 3, NextAttempt: time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)}))
	must(t, store.SetIssuerState(true))
	ipDir := filepath.Join(dir, "iplists")
	must(t, os.MkdirAll(ipDir, 0o700))
	state, _ := json.MarshalIndent(iplists.ProviderState{CIDRs: []string{"1.1.1.0/24", "8.8.4.0/24"}, LastSuccess: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		LastAttempt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC), LastChange: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Held: true,
		Pending: []string{"1.1.1.0/24", "8.8.4.0/24", "9.9.9.0/24"}, HeldReason: "grew by 50%",
		NextAttempt: time.Date(2099, 1, 1, 1, 0, 0, 0, time.UTC)}, "", "  ")
	must(t, os.WriteFile(filepath.Join(ipDir, "cdn.json"), state, 0o600))
	must(t, iplists.AppendHistory(ipDir, "edge", iplists.HistoryEntry{Time: "2026-11-19T08:10:00Z", Event: "held", Provider: "cdn", Version: "v1", PreviousVersion: "v1",
		Added: []string{"9.9.9.0/24"}, Removed: []string{}, AddedCount: 1, CountBefore: 3, CountAfter: 4, Reason: "grew by 50%"}))
	return cfgPath
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestLegacyStatusMatchesOriginMain(t *testing.T) {
	cfg, err := config.LoadConfig(writeLegacyFixture(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	in, err := collectStatus(nil, cfg, true, time.Date(2026, 11, 19, 8, 20, 33, 0, time.UTC))
	must(t, err)
	var got bytes.Buffer
	must(t, writeJSON(&got, report.Legacy(in)))
	want, err := os.ReadFile(filepath.Join("testdata", "status-legacy-origin-main.json"))
	must(t, err)
	if !bytes.Equal(got.Bytes(), want) {
		t.Errorf("the legacy status differs from origin/main's output:\n--- got\n%s\n--- want\n%s", got.Bytes(), want)
	}
}
