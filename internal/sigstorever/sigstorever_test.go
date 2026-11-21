package sigstorever_test

import (
	"os"
	"strings"
	"testing"

	"github.com/KazuhaHub/infra-hub/internal/sigstorever"
	"github.com/KazuhaHub/infra-hub/internal/sigstorever/sigstoretest"
)

var statement = []byte("infra-bundle v1\nrepo KazuhaHub/infra\n")

const repo = "KazuhaHub/infra"

func TestEmbeddedRootParses(t *testing.T) {
	if _, err := sigstorever.EmbeddedRoot(); err != nil {
		t.Fatal(err)
	}
	s, err := sigstorever.RootSummary()
	if err != nil || !strings.Contains(s, "transparency logs") {
		t.Errorf("summary %q, %v", s, err)
	}
}

func TestIdentity(t *testing.T) {
	want := "https://github.com/KazuhaHub/infra/.github/workflows/attest-main.yml@refs/heads/main"
	if got := sigstorever.Identity(repo); got != want {
		t.Errorf("got %q", got)
	}
}

func TestVerify(t *testing.T) {
	f := sigstoretest.New(t)
	id := sigstorever.Identity(repo)
	other := sigstoretest.New(t) // another Sigstore: its root does not know f's certificates
	cases := []struct {
		name     string
		bundle   []byte
		artifact []byte
		tm       *sigstoretest.Fake
		want     string // "" = accepted, otherwise a part of the error
	}{
		{"valid", f.Sign(statement, sigstoretest.Options{}), statement, f, ""},
		{"other repository", f.Sign(statement, sigstoretest.Options{Repo: "Evil/infra"}), statement, f, "expected SAN"},
		{"other workflow", f.Sign(statement, sigstoretest.Options{Identity: "https://github.com/KazuhaHub/infra/.github/workflows/other.yml@refs/heads/main"}), statement, f, "expected SAN"},
		{"other ref", f.Sign(statement, sigstoretest.Options{Identity: "https://github.com/KazuhaHub/infra/.github/workflows/attest-main.yml@refs/heads/feature"}), statement, f, "expected SAN"},
		{"a tag ref", f.Sign(statement, sigstoretest.Options{Identity: "https://github.com/KazuhaHub/infra/.github/workflows/attest-main.yml@refs/tags/v1"}), statement, f, "expected SAN"},
		{"wrong issuer", f.Sign(statement, sigstoretest.Options{Issuer: "https://accounts.google.com"}), statement, f, "issuer"},
		{"digest mismatch", f.Sign(statement, sigstoretest.Options{}), append([]byte("x"), statement...), f, "digest"},
		{"no transparency log entry", f.Sign(statement, sigstoretest.Options{NoTlog: true}), statement, f, ""},
		{"unknown root", f.Sign(statement, sigstoretest.Options{}), statement, other, ""},
		{"not a bundle", []byte(`{"mediaType":"x"}`), statement, f, "not a valid Sigstore bundle"},
		{"not json", []byte("hello"), statement, f, "not a valid Sigstore bundle"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := sigstorever.Verify(c.tm.TrustedMaterial(), c.bundle, c.artifact, sigstorever.Policy{Repo: repo, Relaxed: true})
			switch {
			case c.name == "valid":
				if err != nil {
					t.Fatal(err)
				}
				if res.Identity != id || res.Issuer != sigstorever.Issuer || res.Time.IsZero() {
					t.Errorf("result %+v", res)
				}
			case err == nil:
				t.Fatal("accepted")
			case !strings.Contains(err.Error(), c.want):
				t.Errorf("error %q lacks %q", err, c.want)
			}
		})
	}
}

// The bundle in testdata was made by the real CI of KazuhaHub/infra with the public-good Sigstore; it verifies offline
// against the embedded trusted root.
const (
	realRepoID  = "1462297697" // GitHub's ID of KazuhaHub/infra (certificate extension 1.3.6.1.4.1.57264.1.15)
	realOwnerID = "165913136"  // GitHub's ID of the KazuhaHub organisation (extension 1.3.6.1.4.1.57264.1.17)
	realCommit  = "c5bcff666171f4996f0889326f94822eacd09b6e"
)

func realFiles(t *testing.T) (bundleJSON, statement []byte) {
	t.Helper()
	b, err := os.ReadFile("testdata/bundle.sigstore.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := os.ReadFile("testdata/bundle")
	if err != nil {
		t.Fatal(err)
	}
	return b, s
}

func TestRealCIBundle(t *testing.T) {
	b, stmt := realFiles(t)
	tr, err := sigstorever.EmbeddedRoot()
	if err != nil {
		t.Fatal(err)
	}
	good := sigstorever.Policy{Repo: repo, RepoID: realRepoID, OwnerID: realOwnerID, Commit: realCommit}
	res, err := sigstorever.Verify(tr, b, stmt, good)
	if err != nil {
		t.Fatal(err)
	}
	if res.Identity != sigstorever.Identity(repo) || res.Issuer != sigstorever.Issuer {
		t.Errorf("%+v", res)
	}
	edit := func(f func(*sigstorever.Policy)) sigstorever.Policy { p := good; f(&p); return p }
	bad := map[string]struct {
		p     sigstorever.Policy
		stmt  []byte
		match string
	}{
		"other repository":    {edit(func(p *sigstorever.Policy) { p.Repo = "KazuhaHub/other" }), stmt, "expected SAN"},
		"other owner":         {edit(func(p *sigstorever.Policy) { p.Repo = "Evil/infra" }), stmt, "expected SAN"},
		"wrong repository ID": {edit(func(p *sigstorever.Policy) { p.RepoID = "1" }), stmt, "SourceRepositoryIdentifier"},
		"wrong owner ID":      {edit(func(p *sigstorever.Policy) { p.OwnerID = "2" }), stmt, "SourceRepositoryOwnerIdentifier"},
		"swapped IDs":         {edit(func(p *sigstorever.Policy) { p.RepoID, p.OwnerID = p.OwnerID, p.RepoID }), stmt, "Identifier"},
		"other commit":        {edit(func(p *sigstorever.Policy) { p.Commit = strings.Repeat("0", 40) }), stmt, "SourceRepositoryDigest"},
		"other statement":     {good, append([]byte("x"), stmt...), "digest"},
	}
	for name, c := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := sigstorever.Verify(tr, b, c.stmt, c.p); err == nil || !strings.Contains(err.Error(), c.match) {
				t.Errorf("error %v, want one with %q", err, c.match)
			}
		})
	}
	// Without the commit the digest is not pinned.
	if _, err := sigstorever.Verify(tr, b, stmt, edit(func(p *sigstorever.Policy) { p.Commit = "" })); err != nil {
		t.Error(err)
	}
}

// A certificate of the throwaway Sigstore has no GitHub extensions and no certificate timestamp: the strict policy
// rejects it, so the relaxed one cannot be mistaken for the real one.
func TestStrictPolicyRejectsACertificateWithoutTheExtensions(t *testing.T) {
	f := sigstoretest.New(t)
	b := f.Sign(statement, sigstoretest.Options{})
	_, err := sigstorever.Verify(f.TrustedMaterial(), b, statement, sigstorever.Policy{Repo: repo, RepoID: realRepoID, OwnerID: realOwnerID})
	if err == nil {
		t.Fatal("accepted")
	}
}
