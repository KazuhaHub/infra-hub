package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KazuhaHub/infra-hub/internal/bundle"
	"github.com/KazuhaHub/infra-hub/internal/testutil"
)

// attestationMirror makes the hub's repo a bare clone whose main-attestation branch holds files.
func (h hubDir) attestationMirror(t *testing.T, files map[string]string) {
	t.Helper()
	testutil.NeedTool(t, "git")
	work := t.TempDir()
	testutil.RunGit(t, work, "init", "-q", "-b", "main", ".")
	os.WriteFile(filepath.Join(work, "f"), []byte("x"), 0o644)
	testutil.RunGit(t, work, "add", "-A")
	testutil.RunGit(t, work, "commit", "-q", "-m", "main")
	testutil.RunGit(t, work, "checkout", "-q", "--orphan", "main-attestation")
	testutil.RunGit(t, work, "rm", "-q", "-rf", ".")
	for n, c := range files {
		os.WriteFile(filepath.Join(work, n), []byte(c), 0o644)
	}
	testutil.RunGit(t, work, "add", "-A")
	testutil.RunGit(t, work, "commit", "-q", "-m", "attest")
	testutil.RunGit(t, h.dir, "clone", "-q", "--bare", work, filepath.Join(h.dir, "infra.git"))
}

func TestStatusShowsTheBundle(t *testing.T) {
	const commit = "0123456789abcdef0123456789abcdef01234567"
	st := bundle.Statement{Repo: "KazuhaHub/infra", Ref: "refs/heads/main", Commit: commit, Time: 1790000000, SHA256: strings.Repeat("cd", 32), Size: 3}.String()

	h := newHub(t)
	h.markMirrored(t)
	h.attestationMirror(t, map[string]string{"bundle": st, "bundle.sig": "s", "bundle.tar.gz": "abc"})
	code, out, errs := run(t, "status", "--config", h.config, "-o", "json")
	if code != 0 {
		t.Fatalf("%d %s", code, errs)
	}
	var doc struct {
		Bundle map[string]any `json:"bundle"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Bundle["served"] != true || doc.Bundle["commit"] != commit || doc.Bundle["time"] != "2026-09-21T14:13:20Z" || len(doc.Bundle) != 3 {
		t.Errorf("bundle: %v", doc.Bundle)
	}
	_, table, _ := run(t, "status", "--config", h.config)
	if !strings.Contains(table, "bundle:   0123456789ab (2026-09-21T14:13:20Z)\n") {
		t.Errorf("table:\n%s", table)
	}

	// a broken bundle: the reason is shown
	h2 := newHub(t)
	h2.markMirrored(t)
	h2.attestationMirror(t, map[string]string{"bundle": st, "bundle.sig": "s"})
	_, out, _ = run(t, "status", "--config", h2.config, "-o", "json")
	doc.Bundle = nil
	json.Unmarshal([]byte(out), &doc)
	if doc.Bundle["served"] != false || doc.Bundle["reason"] != "no_bundle" || doc.Bundle["commit"] != nil {
		t.Errorf("broken bundle: %v", doc.Bundle)
	}
	_, table, _ = run(t, "status", "--config", h2.config)
	if !strings.Contains(table, "bundle:   none served (no_bundle: no bundle: bundle.tar.gz is missing)\n") {
		t.Errorf("table:\n%s", table)
	}

	// no fetch yet: stale_mirror
	h3 := newHub(t)
	_, out, _ = run(t, "status", "--config", h3.config, "-o", "json")
	doc.Bundle = nil
	json.Unmarshal([]byte(out), &doc)
	if doc.Bundle["served"] != false || doc.Bundle["reason"] != "stale_mirror" {
		t.Errorf("stale: %v", doc.Bundle)
	}

	// --no-refs reads nothing
	_, out, _ = run(t, "status", "--config", h.config, "--no-refs", "-o", "json")
	if strings.Contains(out, `"bundle"`) {
		t.Errorf("--no-refs shows a bundle:\n%s", out)
	}
	if _, table, _ := run(t, "status", "--config", h.config, "--no-refs"); !strings.Contains(table, "bundle:   not read") {
		t.Errorf("table:\n%s", table)
	}
}
