package sigstorever_test

import (
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
			res, err := sigstorever.Verify(c.tm.TrustedMaterial(), c.bundle, c.artifact, id)
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
