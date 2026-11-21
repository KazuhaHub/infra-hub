package bundle

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/testutil"
)

const (
	goodCommit = "0123456789abcdef0123456789abcdef01234567"
	goodSHA    = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func goodText() string {
	return "infra-bundle v1\nrepo KazuhaHub/infra\nref refs/heads/main\ncommit " + goodCommit + "\ntime 1790000000\nsha256 " + goodSHA + "\nsize 1234\n"
}

func TestParseStatementGood(t *testing.T) {
	s, err := ParseStatement([]byte(goodText()))
	if err != nil {
		t.Fatal(err)
	}
	want := Statement{Repo: "KazuhaHub/infra", Ref: "refs/heads/main", Commit: goodCommit, Time: 1790000000, SHA256: goodSHA, Size: 1234}
	if s != want {
		t.Fatalf("got %+v", s)
	}
	if s.String() != goodText() {
		t.Fatalf("String() = %q", s.String())
	}
	if _, err := ParseStatement([]byte(strings.Replace(goodText(), "size 1234", "size 0", 1))); err != nil {
		t.Errorf("size 0: %v", err)
	}
	for _, tm := range []string{"1", "8589934591"} {
		if _, err := ParseStatement([]byte(strings.Replace(goodText(), "time 1790000000", "time "+tm, 1))); err != nil {
			t.Errorf("time %s: %v", tm, err)
		}
	}
}

func TestParseStatementRefusals(t *testing.T) {
	g := goodText()
	rep := func(old, new string) string { return strings.Replace(g, old, new, 1) }
	lines := strings.Split(strings.TrimSuffix(g, "\n"), "\n")
	join := func(l []string) string { return strings.Join(l, "\n") + "\n" }
	swapped := append([]string{}, lines...)
	swapped[1], swapped[2] = swapped[2], swapped[1]
	cases := map[string]string{
		"empty":                "",
		"only newline":         "\n",
		"no final newline":     strings.TrimSuffix(g, "\n"),
		"two final newlines":   g + "\n",
		"CRLF":                 strings.ReplaceAll(g, "\n", "\r\n"),
		"bare CR":              rep("repo ", "repo\r"),
		"wrong header":         rep("infra-bundle v1", "infra-bundle v2"),
		"header case":          rep("infra-bundle v1", "Infra-Bundle v1"),
		"header trailing":      rep("infra-bundle v1", "infra-bundle v1 "),
		"missing line":         join(lines[:6]),
		"extra line":           g + "extra x\n",
		"extra blank line":     rep("ref ", "\nref "),
		"swapped order":        join(swapped),
		"duplicate key":        join(append(append([]string{}, lines...), "size 1")),
		"two spaces":           rep("repo K", "repo  K"),
		"tab separator":        rep("repo K", "repo\tK"),
		"no value":             rep("repo KazuhaHub/infra", "repo "),
		"no space no value":    rep("repo KazuhaHub/infra", "repo"),
		"trailing space":       rep("size 1234", "size 1234 "),
		"leading space value":  rep("time 1790000000", "time  1790000000"),
		"repo no slash":        rep("KazuhaHub/infra", "KazuhaHubinfra"),
		"repo two slashes":     rep("KazuhaHub/infra", "a/b/c"),
		"repo with space":      rep("KazuhaHub/infra", "Kazuha Hub/infra"),
		"repo empty part":      rep("KazuhaHub/infra", "/infra"),
		"ref other branch":     rep("refs/heads/main", "refs/heads/other"),
		"ref short":            rep("refs/heads/main", "main"),
		"ref tag":              rep("refs/heads/main", "refs/tags/main"),
		"commit short":         rep(goodCommit, goodCommit[:39]),
		"commit long":          rep(goodCommit, goodCommit+"0"),
		"commit upper":         rep(goodCommit, strings.ToUpper(goodCommit)),
		"commit non-hex":       rep(goodCommit, "g"+goodCommit[1:]),
		"commit sha256 length": rep(goodCommit, goodSHA),
		"sha short":            rep(goodSHA, goodSHA[:63]),
		"sha upper":            rep(goodSHA, strings.ToUpper(goodSHA)),
		"sha non-hex":          rep(goodSHA, "z"+goodSHA[1:]),
		"time negative":        rep("time 1790000000", "time -1"),
		"time plus":            rep("time 1790000000", "time +1"),
		"time leading zero":    rep("time 1790000000", "time 01790000000"),
		"time float":           rep("time 1790000000", "time 1790000000.5"),
		"time hex":             rep("time 1790000000", "time 0x10"),
		"time letters":         rep("time 1790000000", "time soon"),
		"time huge":            rep("time 1790000000", "time 99999999999999999999"),
		"time out of range":    rep("time 1790000000", "time 8589934592"),
		"time zero":            rep("time 1790000000", "time 0"),
		"size negative":        rep("size 1234", "size -5"),
		"size leading zero":    rep("size 1234", "size 0123"),
		"size underscore":      rep("size 1234", "size 1_234"),
		"size huge":            rep("size 1234", "size 99999999999999999999"),
		"size empty":           rep("size 1234", "size "),
		"NUL byte":             rep("repo ", "repo \x00"),
		"non-ASCII":            rep("KazuhaHub", "Kazuhä"),
		"tab in text":          rep("infra-bundle", "infra\t-bundle"),
		"bom":                  "\xef\xbb\xbf" + g,
		"too large":            g + strings.Repeat("x", MaxStatement),
	}
	for name, in := range cases {
		if _, err := ParseStatement([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func FuzzParseStatement(f *testing.F) {
	f.Add([]byte(goodText()))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := ParseStatement(b)
		if err == nil && s.String() != string(b) {
			t.Fatalf("accepted %q but it re-renders as %q", b, s.String())
		}
	})
}

func TestArchive(t *testing.T) {
	f := Files{Statement: []byte(goodText()), Signature: []byte("sig"), Tarball: []byte("tarball bytes")}
	mt := time.Unix(1790000000, 0)
	data, err := Archive(f, mt, Format1)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(bytes.NewReader(data))
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
		if h.Typeflag != tar.TypeReg || h.Mode != 0o644 || h.Uid != 0 || h.Gid != 0 || !h.ModTime.Equal(mt) || h.Format != tar.FormatUSTAR {
			t.Errorf("%s: header %+v", h.Name, h)
		}
	}
	if strings.Join(names, ",") != "bundle,bundle.sig,bundle.tar.gz" {
		t.Errorf("members %v", names)
	}
}

// attestationRepo is a git repository whose main-attestation branch holds files; it returns the git dir.
func attestationRepo(t *testing.T, files map[string]string) (gitDir, work string) {
	t.Helper()
	testutil.NeedTool(t, "git")
	work = t.TempDir()
	testutil.RunGit(t, work, "init", "-q", "-b", "main", ".")
	testutil.RunGit(t, work, "checkout", "-q", "--orphan", "main-attestation")
	commitFiles(t, work, files)
	return filepath.Join(work, ".git"), work
}

// commitFiles replaces the content of work with files and commits it.
func commitFiles(t *testing.T, work string, files map[string]string) {
	t.Helper()
	for _, n := range []string{StatementName, SignatureName, TarballName, SigstoreName} {
		os.Remove(filepath.Join(work, n))
	}
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(work, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	testutil.RunGit(t, work, "add", "-A")
	testutil.RunGit(t, work, "commit", "-q", "--allow-empty", "-m", "attest")
}

func TestLoad(t *testing.T) {
	files := map[string]string{"bundle": goodText(), "bundle.sig": "SIG", "bundle.tar.gz": "TARBALL"}
	repo, _ := attestationRepo(t, files)
	l, err := Load(context.Background(), repo, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if string(l.Files.Statement) != goodText() || string(l.Files.Signature) != "SIG" || string(l.Files.Tarball) != "TARBALL" || l.Statement.Commit != goodCommit || len(l.Tip) != 40 {
		t.Fatalf("%+v", l)
	}

	bad := map[string]struct {
		files map[string]string
		lim   Limits
	}{
		"missing tarball":    {map[string]string{"bundle": goodText(), "bundle.sig": "SIG"}, DefaultLimits},
		"missing signature":  {map[string]string{"bundle": goodText(), "bundle.tar.gz": "T"}, DefaultLimits},
		"missing statement":  {map[string]string{"bundle.sig": "S", "bundle.tar.gz": "T"}, DefaultLimits},
		"bad statement":      {map[string]string{"bundle": "nonsense\n", "bundle.sig": "S", "bundle.tar.gz": "T"}, DefaultLimits},
		"tarball over limit": {files, Limits{Tarball: 3, Statement: MaxStatement, Signature: MaxSignature}},
		"sig over limit":     {files, Limits{Tarball: MaxTarball, Statement: MaxStatement, Signature: 1}},
		"stmt over limit":    {files, Limits{Tarball: MaxTarball, Statement: 10, Signature: MaxSignature}},
	}
	for name, c := range bad {
		repo, _ := attestationRepo(t, c.files)
		if _, err := Load(context.Background(), repo, c.lim); !errors.Is(err, ErrNoBundle) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// a directory named like a file is not a file
	repo, work := attestationRepo(t, map[string]string{"bundle": goodText(), "bundle.sig": "S"})
	os.MkdirAll(filepath.Join(work, "bundle.tar.gz"), 0o755)
	os.WriteFile(filepath.Join(work, "bundle.tar.gz", "x"), []byte("x"), 0o644)
	testutil.RunGit(t, work, "add", "-A")
	testutil.RunGit(t, work, "commit", "-q", "-m", "dir")
	if _, err := Load(context.Background(), repo, DefaultLimits); !errors.Is(err, ErrNoBundle) {
		t.Errorf("directory: err = %v", err)
	}
	// no main-attestation branch at all
	empty := t.TempDir()
	testutil.RunGit(t, empty, "init", "-q", "--bare", ".")
	if _, err := Load(context.Background(), empty, DefaultLimits); !errors.Is(err, ErrNoBundle) {
		t.Errorf("no branch: err = %v", err)
	}
}

func TestArchiveErrorIsNoBundle(t *testing.T) {
	f := Files{Statement: []byte("a"), Signature: []byte("b"), Tarball: []byte("c")}
	for _, tm := range []time.Time{time.Unix(8589934592, 0), time.Unix(-1, 0)} {
		if _, err := Archive(f, tm, Format1); !errors.Is(err, ErrNoBundle) {
			t.Errorf("mtime %v: err = %v", tm, err)
		}
	}
}

func TestLoadStatementReadsOnlyTheStatement(t *testing.T) {
	repo, _ := attestationRepo(t, map[string]string{"bundle": goodText()}) // no signature, no tarball
	tip, err := Tip(context.Background(), repo)
	if err != nil {
		t.Fatal(err)
	}
	if st, err := LoadStatement(context.Background(), repo, tip, DefaultLimits); err != nil || st.Commit != goodCommit {
		t.Errorf("LoadStatement: %+v %v", st, err)
	}
	if _, err := Inspect(context.Background(), repo, tip, DefaultLimits); !errors.Is(err, ErrNoBundle) {
		t.Errorf("Inspect with missing files: %v", err)
	}
	if _, err := LoadStatement(context.Background(), repo, tip, Limits{Statement: 5}); !errors.Is(err, ErrNoBundle) {
		t.Errorf("statement over limit: %v", err)
	}
}

func TestLoadReadsTheOptionalFourthFile(t *testing.T) {
	files := map[string]string{"bundle": goodText(), "bundle.sig": "SIG", "bundle.tar.gz": "TARBALL"}
	repo, _ := attestationRepo(t, files)
	l, err := Load(context.Background(), repo, DefaultLimits)
	if err != nil || l.Files.Sigstore != nil {
		t.Fatalf("without the file: %v, %q", err, l.Files.Sigstore)
	}
	files["bundle.sigstore.json"] = `{"mediaType":"x"}`
	repo, _ = attestationRepo(t, files)
	l, err = Load(context.Background(), repo, DefaultLimits)
	if err != nil || string(l.Files.Sigstore) != `{"mediaType":"x"}` {
		t.Fatalf("with the file: %v, %q", err, l.Files.Sigstore)
	}
	// Over its limit, the file is left out and the bundle stays usable.
	l, err = Load(context.Background(), repo, Limits{Tarball: MaxTarball, Statement: MaxStatement, Signature: MaxSignature, Sigstore: 5})
	if err != nil || l.Files.Sigstore != nil {
		t.Fatalf("over the limit: %v, %q", err, l.Files.Sigstore)
	}
}

func TestArchiveFormats(t *testing.T) {
	f := Files{Statement: []byte(goodText()), Signature: []byte("sig"), Tarball: []byte("tarball bytes"), Sigstore: []byte("{}")}
	names := func(format int, f Files) string {
		data, err := Archive(f, time.Unix(1790000000, 0), format)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		tr := tar.NewReader(bytes.NewReader(data))
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, h.Name)
		}
		return strings.Join(out, ",")
	}
	if got := names(Format1, f); got != "bundle,bundle.sig,bundle.tar.gz" {
		t.Errorf("format 1: %s", got)
	}
	if got := names(Format2, f); got != "bundle,bundle.sig,bundle.tar.gz,bundle.sigstore.json" {
		t.Errorf("format 2: %s", got)
	}
	f.Sigstore = nil
	if got := names(Format2, f); got != "bundle,bundle.sig,bundle.tar.gz" {
		t.Errorf("format 2 without the file: %s", got)
	}
}
