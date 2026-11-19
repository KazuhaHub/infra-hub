package gitmirror_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/KazuhaHub/infra-hub/internal/gitmirror"
	"github.com/KazuhaHub/infra-hub/internal/testutil"
)

func TestMirrorCarriesOnlyMainAndAttestation(t *testing.T) {
	upstream, work := testutil.MakeUpstream(t)
	m := &gitmirror.Mirror{Repo: filepath.Join(t.TempDir(), "infra.git"), Upstream: upstream}
	ctx := context.Background()
	if err := m.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	refs, _ := gitmirror.ReadRefs(ctx, m.Repo)
	if len(refs) != 2 || refs["refs/heads/main"] == "" || refs["refs/heads/main-attestation"] == "" {
		t.Fatalf("refs = %v (the extra branch must not be mirrored)", refs)
	}
	// main moves on upstream: the mirror follows (forced), still only two refs
	testutil.RunGit(t, work, "commit", "-q", "--allow-empty", "-m", "c2")
	testutil.RunGit(t, work, "push", "-q", upstream, "main")
	if err := m.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	refs2, _ := gitmirror.ReadRefs(ctx, m.Repo)
	if refs2["refs/heads/main"] != testutil.RunGit(t, work, "rev-parse", "main") || len(refs2) != 2 {
		t.Fatalf("refs = %v", refs2)
	}
	// an upstream that lost the attestation branch is an error, and what the mirror had stays
	testutil.RunGit(t, work, "push", "-q", upstream, ":refs/heads/main-attestation")
	if err := m.Fetch(ctx); err == nil {
		t.Fatal("fetch should fail without the attestation branch")
	}
	if refs3, _ := gitmirror.ReadRefs(ctx, m.Repo); refs3["refs/heads/main-attestation"] == "" {
		t.Fatal("mirror lost the attestation ref on a failed fetch")
	}
}
