package app

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KazuhaHub/infra-hub/internal/state"
)

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

func TestStatusShowsRejectedHubs(t *testing.T) {
	h := newHub(t)
	h.markMirrored(t)
	st, err := state.LoadState(filepath.Join(h.dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	st.SetReport("h1", state.HostReport{Result: "verified", Time: "2026-11-19T08:10:00Z", ReceivedAt: "2026-11-19T08:10:02Z", RejectedHubs: []string{"https://hub1.example.org:8443"}})
	if err := st.Flush(); err != nil {
		t.Fatal(err)
	}
	_, out, _ := run(t, "status", "--config", h.config, "--no-refs", "-o", "json")
	var doc struct {
		Hosts []struct {
			Report struct{ RejectedHubs []string }
		}
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || len(doc.Hosts[0].Report.RejectedHubs) != 1 {
		t.Errorf("json: %v\n%s", err, out)
	}
	if _, table, _ := run(t, "status", "--config", h.config, "--no-refs"); !strings.Contains(table, "rejected-by https://hub1.example.org:8443") {
		t.Errorf("table:\n%s", table)
	}
}
