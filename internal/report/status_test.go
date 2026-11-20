package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/certs"
	"github.com/KazuhaHub/infra-hub/internal/iplists"
	"github.com/KazuhaHub/infra-hub/internal/state"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func sp(s string) *string { return &s }

func fixture() StatusInput {
	now := time.Date(2026, 11, 19, 8, 20, 33, 0, time.UTC)
	return StatusInput{
		Now:               now,
		Main:              "1111111111111111111111111111111111111111",
		MainAttestation:   "2222222222222222222222222222222222222222",
		MirrorLastSuccess: now.Add(-95 * time.Second),
		Hosts: map[string]state.NodeRecord{
			"web-2":  {LastSeen: now.Add(-3 * time.Minute), Main: "1111111111111111111111111111111111111111", MainAttestation: "2222222222222222222222222222222222222222"},
			"app-1":  {LastSeen: now.Add(-10 * time.Second), Main: "1111111111111111111111111111111111111111"},
			"spare3": {}, // configured, never fetched
		},
		Issuer: "enabled",
		Certs: map[string]certs.CertStatus{
			"b.example.org": {Owner: "web-2", NotAfter: sp("2027-01-17T00:00:00Z"), LastAttempt: sp("2026-11-18T03:00:00Z"), LastResult: "ok"},
			"a.example.org": {Owner: "app-1", LastAttempt: sp("2026-11-19T08:00:00Z"), LastResult: "error", LastError: "dns timeout", Failures: 3, Failing: true,
				NextAttempt: sp("2026-11-19T12:00:00Z")},
		},
		IPLists: &iplists.IPStatus{
			Providers: map[string]iplists.ProviderStatus{
				"fastly":     {LastSuccess: sp("2026-11-19T08:10:00Z"), Count: 40, LastChange: sp("2026-11-01T00:00:00Z")},
				"cloudflare": {LastSuccess: sp("2026-11-19T08:10:00Z"), Count: 22, LastChange: sp("2026-11-19T08:10:00Z"), Held: true, HeldReason: "grew by 60%", Pending: 36},
			},
			Lists: map[string]iplists.ListStatus{
				"edge": {Providers: []string{"cloudflare", "fastly"}, Manual: 1, Hosts: []string{"app-1", "web-2"}, Entries: 63, Version: "0123456789abcdef",
					Warnings: []string{}, History: []iplists.HistoryEntry{{Time: "2026-11-19T08:10:00Z", Event: "held", Provider: "cloudflare", Version: "0123456789abcdef",
						PreviousVersion: "0123456789abcdef", Added: []string{"198.51.100.0/24"}, Removed: []string{}, AddedCount: 1, CountBefore: 22, CountAfter: 36, Reason: "grew by 60%"}}},
			},
		},
	}
}

func golden(t *testing.T, name string, v any) {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("%s differs (run go test ./internal/report -update to accept):\n--- got\n%s\n--- want\n%s", name, buf.Bytes(), want)
	}
}

func TestStatusGoldenV1(t *testing.T) { golden(t, "status-v1.json", NewStatus(fixture())) }

// The legacy document is checked against the real output of origin/main in internal/app (legacy_golden_test.go).

func TestStatusGoldenEmpty(t *testing.T) {
	in := StatusInput{Now: time.Date(2026, 11, 19, 8, 20, 33, 0, time.UTC), Issuer: "disabled"}
	golden(t, "status-empty-v1.json", NewStatus(in))
}

// The new document follows the conventions: apiVersion, lower camelCase keys, no maps keyed by data, no null.
func TestStatusV1FollowsConventions(t *testing.T) {
	for _, in := range []StatusInput{fixture(), {Now: fixture().Now}} {
		data, _ := json.Marshal(NewStatus(in))
		if strings.Contains(string(data), "null") {
			t.Errorf("null in %s", data)
		}
		var doc map[string]any
		json.Unmarshal(data, &doc)
		if doc["apiVersion"] != "v1" {
			t.Errorf("apiVersion %v", doc["apiVersion"])
		}
		checkKeys(t, "", doc)
	}
}

func checkKeys(t *testing.T, path string, v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			if strings.Contains(k, "_") || k == "" || k[0] < 'a' || k[0] > 'z' {
				t.Errorf("key %s.%s is not lower camelCase", path, k)
			}
			checkKeys(t, path+"."+k, child)
		}
	case []any:
		for _, child := range x {
			checkKeys(t, path+"[]", child)
		}
	case string:
		if strings.HasSuffix(path, "Seconds") {
			t.Errorf("%s is a string", path)
		}
		// every time is RFC 3339 in UTC
		if strings.HasSuffix(path, "At") || strings.Contains(path, "lastSeen") || strings.Contains(path, "notAfter") {
			if _, err := time.Parse(time.RFC3339, x); err != nil || !strings.HasSuffix(x, "Z") {
				t.Errorf("%s = %q is not RFC 3339 UTC", path, x)
			}
		}
	}
}

func TestListsAreSortedByName(t *testing.T) {
	s := NewStatus(fixture())
	if s.Hosts[0].Name != "app-1" || s.Hosts[2].Name != "web-2" || s.Certs[0].Name != "a.example.org" || s.IPLists.Providers[0].Name != "cloudflare" {
		t.Errorf("not sorted: %+v", s)
	}
}

func TestStatusBundle(t *testing.T) {
	in := StatusInput{Now: fixture().Now, Bundle: &BundleInput{Commit: "0123456789abcdef0123456789abcdef01234567", Time: time.Unix(1790000000, 0)}}
	data, _ := json.Marshal(NewStatus(in).Bundle)
	if string(data) != `{"served":true,"commit":"0123456789abcdef0123456789abcdef01234567","time":"2026-09-21T14:13:20Z"}` {
		t.Errorf("served: %s", data)
	}
	in.Bundle = &BundleInput{Reason: "stale_mirror", Message: "the mirror is out of date"}
	data, _ = json.Marshal(NewStatus(in).Bundle)
	if string(data) != `{"served":false,"reason":"stale_mirror","message":"the mirror is out of date"}` {
		t.Errorf("not served: %s", data)
	}
	if NewStatus(StatusInput{Now: in.Now}).Bundle != nil {
		t.Error("an unexamined bundle must be omitted")
	}
}
