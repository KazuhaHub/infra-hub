package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/KazuhaHub/infra-hub/internal/logx"
)

var hex64 = regexp.MustCompile(`[0-9a-f]{64}`)

func captureLogs(buf *bytes.Buffer) func() {
	old := slog.Default()
	l, _ := logx.New(buf, "text", "debug")
	slog.SetDefault(l)
	return func() { slog.SetDefault(old) }
}

type tent struct {
	name, data, link string
	typ              byte
	mode             int64
}

func tarEntries(t *testing.T, es ...tent) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range es {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		mode := e.mode
		if mode == 0 {
			mode = 0o644
		}
		h := &tar.Header{Name: e.name, Typeflag: typ, Mode: mode, Linkname: e.link}
		if typ == tar.TypeReg {
			h.Size = int64(len(e.data))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			tw.Write([]byte(e.data))
		}
	}
	tw.Close()
	return buf.Bytes()
}

func gz(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(plain)
	zw.Close()
	return buf.Bytes()
}

func extractInto(t *testing.T, es ...tent) (string, error) {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "x")
	if err := os.Mkdir(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	return dst, ExtractTar(dst, bytes.NewReader(gz(t, tarEntries(t, es...))))
}

func TestExtractGoodTree(t *testing.T) {
	dst, err := extractInto(t,
		tent{name: "infra/", typ: tar.TypeDir},
		tent{name: "infra/site.yml", data: "- hosts: all\n"},
		tent{name: "infra/bin/run.sh", data: "#!/bin/sh\n", mode: 0o4755}, // setuid must not survive
		tent{name: "infra/link", typ: tar.TypeSymlink, link: "site.yml"},
		tent{name: "infra/a/b/up", typ: tar.TypeSymlink, link: "../../site.yml"},
		tent{name: "infra/hard", typ: tar.TypeLink, link: "infra/site.yml"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "infra", "link")); string(b) != "- hosts: all\n" {
		t.Errorf("symlink content %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "infra", "a", "b", "up")); string(b) != "- hosts: all\n" {
		t.Errorf("deep symlink content %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "infra", "hard")); string(b) != "- hosts: all\n" {
		t.Errorf("hard link content %q", b)
	}
	st, _ := os.Stat(filepath.Join(dst, "infra", "bin", "run.sh"))
	if st.Mode()&fs.ModeSetuid != 0 || st.Mode().Perm() != 0o755 {
		t.Errorf("mode %v", st.Mode())
	}
}

func TestExtractRefusesHostileTarballs(t *testing.T) {
	cases := map[string][]tent{
		"dot dot":            {{name: "infra/../../evil", data: "x"}},
		"leading dot dot":    {{name: "../evil", data: "x"}},
		"absolute":           {{name: "/etc/cron.d/evil", data: "x"}},
		"absolute dir":       {{name: "/tmp/", typ: tar.TypeDir}},
		"symlink absolute":   {{name: "infra/l", typ: tar.TypeSymlink, link: "/etc/passwd"}},
		"symlink up":         {{name: "infra/l", typ: tar.TypeSymlink, link: "../../x"}},
		"symlink up at root": {{name: "l", typ: tar.TypeSymlink, link: "../x"}},
		"symlink dot dot in": {{name: "infra/l", typ: tar.TypeSymlink, link: "a/../../../x"}},
		"write through link": {{name: "infra/d", typ: tar.TypeSymlink, link: "."}, {name: "infra/d/f", data: "x"}},
		"link then escape":   {{name: "d", typ: tar.TypeSymlink, link: "."}, {name: "d/e/up", typ: tar.TypeSymlink, link: "../.."}},
		"hard link outside":  {{name: "infra/h", typ: tar.TypeLink, link: "/etc/passwd"}},
		"hard link dot dot":  {{name: "infra/h", typ: tar.TypeLink, link: "../x"}},
		"hard link unknown":  {{name: "infra/h", typ: tar.TypeLink, link: "infra/nothing"}},
		"device":             {{name: "infra/dev", typ: tar.TypeChar}},
		"block device":       {{name: "infra/dev", typ: tar.TypeBlock}},
		"fifo":               {{name: "infra/f", typ: tar.TypeFifo}},
		"duplicate file":     {{name: "infra/a", data: "1"}, {name: "infra/a", data: "2"}},
		"backslash":          {{name: `infra\..\evil`, data: "x"}},
	}
	for name, es := range cases {
		t.Run(name, func(t *testing.T) {
			dst, err := extractInto(t, es...)
			if err == nil {
				t.Fatal("accepted")
			}
			if _, ok := err.(*RejectError); !ok {
				t.Errorf("error %T %v, want a RejectError", err, err)
			}
			// Nothing may have been written outside dst.
			parent, _ := os.ReadDir(filepath.Dir(dst))
			if len(parent) != 1 {
				t.Errorf("files next to the target: %v", parent)
			}
		})
	}
}

func TestExtractSizeCap(t *testing.T) {
	old := extractLimit
	extractLimit = 20 << 10
	defer func() { extractLimit = old }()
	_, err := extractInto(t, tent{name: "infra/big", data: strings.Repeat("a", 64<<10)})
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("err %v", err)
	}
	// A gzip bomb: tiny compressed, huge unpacked.
	dst := t.TempDir()
	zeros := tarEntries(t, tent{name: "infra/z", data: strings.Repeat("\x00", 4<<20)})
	if err := ExtractTar(dst, bytes.NewReader(gz(t, zeros))); err == nil {
		t.Fatal("the bomb was accepted")
	}
}

func TestExtractWholeReleaseIsAtomic(t *testing.T) {
	state := t.TempDir()
	commit := strings.Repeat("ab", 20)
	good := gz(t, tarEntries(t, tent{name: "infra/", typ: tar.TypeDir}, tent{name: "infra/site.yml", data: "x"}))
	dir, err := Extract(state, commit, good)
	if err != nil || dir != ReleaseDir(state, commit) {
		t.Fatalf("%q, %v", dir, err)
	}
	// A failing extraction leaves neither a release nor a temporary directory, and does not touch an existing release.
	bad := gz(t, tarEntries(t, tent{name: "infra/ok", data: "x"}, tent{name: "../bad", data: "x"}))
	if _, err := Extract(state, strings.Repeat("cd", 20), bad); err == nil {
		t.Fatal("accepted")
	}
	entries, _ := os.ReadDir(filepath.Join(state, "releases"))
	if len(entries) != 1 || entries[0].Name() != commit {
		t.Errorf("releases dir: %v", entries)
	}
	// No infra/ directory is refused as well.
	if _, err := Extract(state, strings.Repeat("ef", 20), gz(t, tarEntries(t, tent{name: "other/x", data: "x"}))); err == nil {
		t.Error("a bundle without infra/ was accepted")
	}
}
