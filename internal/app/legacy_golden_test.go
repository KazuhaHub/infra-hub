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
	"github.com/KazuhaHub/infra-hub/internal/testutil"
)

// testdata/status-legacy-origin-main.json is the output of the binary built from origin/main (commit f9fdeeb, the
// last commit before the conventions change) for `infra-hub status -config <dir>/config.json -no-refs`, run against
// the state tree that writeLegacyFixture creates. Only the two values that depend on the wall clock were replaced:
// "time" by 2026-11-19T08:20:33Z and "mirror_age_seconds" by 95 (the mirror success is 95 s before that time).
//
// To regenerate: go test ./internal/app -run TestWriteLegacyFixture -fixture-dir=$DIR; build origin/main; run its
// `status -config $DIR/config.json -no-refs`; substitute those two values.
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
	_, k1 := testutil.NewKey(t)
	_, k2 := testutil.NewKey(t)
	cfgData, _ := json.Marshal(map[string]any{
		"listen": "127.0.0.1:11882", "repo": filepath.Join(dir, "infra.git"), "upstream": "git@example.invalid:x/infra.git",
		"hostKey": filepath.Join(dir, "host_key"), "clients": map[string]string{"h1": k1, "h2": k2},
		"certs":     map[string]string{"a.example.org": "h1", "b.example.org": "h2"},
		"ipSources": map[string]any{"cdn": map[string]any{"url": "https://example.invalid/ips", "format": "lines"}},
		"ipLists":   map[string]any{"edge": map[string]any{"providers": []string{"cdn"}, "manual": []string{"8.8.8.0/24"}, "hosts": []string{"h1", "h2"}}},
	})
	cfgPath := filepath.Join(dir, "config.json")
	must(t, os.MkdirAll(dir, 0o700))
	must(t, os.WriteFile(cfgPath, cfgData, 0o600))
	must(t, os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{
  "mirror_last_success": "2026-11-19T08:18:58Z",
  "hosts": {"h2": {"last_seen": "2026-11-19T08:17:33Z", "main": "1111111111111111111111111111111111111111", "main_attestation": "2222222222222222222222222222222222222222"}}
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
