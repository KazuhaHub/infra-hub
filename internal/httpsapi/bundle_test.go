package httpsapi

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/KazuhaHub/infra-hub/internal/bundle"
	"github.com/KazuhaHub/infra-hub/internal/gitmirror"
	"github.com/KazuhaHub/infra-hub/internal/testutil"
)

func statementFor(c string, tm int64) string {
	return bundle.Statement{Repo: "KazuhaHub/infra", Ref: "refs/heads/main", Commit: c, Time: tm,
		SHA256: strings.Repeat("ab", 32), Size: 7}.String()
}

func c40(n int) string { return fmt.Sprintf("%040x", n) }

// attest is a git repository whose main-attestation branch carries the bundle files.
type attest struct {
	t    *testing.T
	work string
	repo string
}

func newAttest(t *testing.T, files map[string]string) *attest {
	t.Helper()
	testutil.NeedTool(t, "git")
	a := &attest{t: t, work: t.TempDir()}
	testutil.RunGit(t, a.work, "init", "-q", "-b", "main", ".")
	testutil.RunGit(t, a.work, "checkout", "-q", "--orphan", "main-attestation")
	a.repo = filepath.Join(a.work, ".git")
	a.commit(files)
	return a
}

func (a *attest) commit(files map[string]string) {
	a.t.Helper()
	for _, n := range []string{"bundle", "bundle.sig", "bundle.tar.gz"} {
		os.Remove(filepath.Join(a.work, n))
	}
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(a.work, n), []byte(c), 0o644); err != nil {
			a.t.Fatal(err)
		}
	}
	testutil.RunGit(a.t, a.work, "add", "-A")
	testutil.RunGit(a.t, a.work, "commit", "-q", "--allow-empty", "-m", "attest")
}

func goodFiles(n int) map[string]string {
	return map[string]string{
		"bundle":        statementFor(c40(n), 1790000000+int64(n)),
		"bundle.sig":    "-----BEGIN SSH SIGNATURE-----\nfake " + fmt.Sprint(n) + "\n-----END SSH SIGNATURE-----\n",
		"bundle.tar.gz": "\x1f\x8b binary \x00\x01\x02 tarball " + fmt.Sprint(n) + strings.Repeat("\xff", 5000),
	}
}

type bundleResp struct {
	code   int
	header http.Header
	body   []byte
}

func (h *testHub) getBundle(t *testing.T, method, host string, hdr map[string]string) bundleResp {
	t.Helper()
	return h.getBundleFrom(t, "192.0.2.1:1234", method, host, hdr)
}

func (h *testHub) getBundleFrom(t *testing.T, remote, method, host string, hdr map[string]string) bundleResp {
	t.Helper()
	req, _ := http.NewRequest(method, "https://hub.example.org/v1/bundle/"+host, nil)
	req.RemoteAddr = remote
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := &recorder{header: http.Header{}, code: 200}
	h.s.Handler().ServeHTTP(rec, req)
	return bundleResp{rec.code, rec.header, rec.body.Bytes()}
}

func errCodeOf(t *testing.T, r bundleResp) string {
	t.Helper()
	if r.header.Get("Content-Type") != "application/json" {
		t.Errorf("error content type %q", r.header.Get("Content-Type"))
	}
	doc := map[string]any{}
	if err := json.Unmarshal(r.body, &doc); err != nil || doc["apiVersion"] != "v1" {
		t.Fatalf("not an error document: %q", r.body)
	}
	return errCode(doc)
}

// members decrypts body with id and returns the tar members in order.
func members(t *testing.T, id *age.X25519Identity, body []byte) (names []string, data map[string][]byte, hdrs []*tar.Header) {
	t.Helper()
	if bytes.HasPrefix(body, []byte("-----BEGIN")) {
		t.Fatal("the body is armored; it must be binary age")
	}
	r, err := age.Decrypt(bytes.NewReader(body), id)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(bytes.NewReader(plain))
	data = map[string][]byte{}
	for {
		hd, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		names = append(names, hd.Name)
		data[hd.Name] = b
		hdrs = append(hdrs, hd)
	}
	return
}

func withBundles(t *testing.T, a *attest) *testHub {
	h := newHub(t)
	h.s.Bundles = &Bundles{Repo: a.repo}
	return h
}

func TestBundleServed(t *testing.T) {
	files := goodFiles(1)
	h := withBundles(t, newAttest(t, files))
	r := h.getBundle(t, "GET", "h1", nil)
	if r.code != 200 {
		t.Fatalf("%d %s", r.code, r.body)
	}
	if r.header.Get("Content-Type") != "application/octet-stream" || r.header.Get("Cache-Control") != "no-store" ||
		r.header.Get("ETag") != `"`+c40(1)+`"` || r.header.Get("Content-Length") != fmt.Sprint(len(r.body)) {
		t.Errorf("headers %v", r.header)
	}
	names, data, hdrs := members(t, h.ids["h1"], r.body)
	if strings.Join(names, ",") != "bundle,bundle.sig,bundle.tar.gz" {
		t.Fatalf("members %v", names)
	}
	for n, want := range files {
		if string(data[n]) != want {
			t.Errorf("%s differs", n)
		}
	}
	for _, hd := range hdrs {
		if hd.Typeflag != tar.TypeReg || hd.Mode != 0o644 || hd.Uid != 0 || hd.Gid != 0 || hd.ModTime.Unix() != 1790000001 || hd.Format != tar.FormatUSTAR {
			t.Errorf("%s: %+v", hd.Name, hd)
		}
	}
	// only the host's own key opens it
	if _, err := age.Decrypt(bytes.NewReader(r.body), h.ids["h2"]); err == nil {
		t.Error("another host's key decrypted the bundle")
	}
	// HEAD: headers, no body
	hr := h.getBundle(t, "HEAD", "h1", nil)
	if hr.code != 200 || len(hr.body) != 0 || hr.header.Get("ETag") != r.header.Get("ETag") {
		t.Errorf("HEAD: %d, %d body bytes, %v", hr.code, len(hr.body), hr.header)
	}
}

func TestBundleNotModified(t *testing.T) {
	h := withBundles(t, newAttest(t, goodFiles(1)))
	etag := `"` + c40(1) + `"`
	for _, inm := range []string{etag, `W/` + etag, `"other", ` + etag, "*"} {
		r := h.getBundle(t, "GET", "h1", map[string]string{"If-None-Match": inm})
		if r.code != 304 || len(r.body) != 0 || r.header.Get("ETag") != etag || r.header.Get("Cache-Control") != "no-store" {
			t.Errorf("If-None-Match %q: %d %v body %d", inm, r.code, r.header, len(r.body))
		}
	}
	r := h.getBundle(t, "GET", "h1", map[string]string{"If-None-Match": `"` + c40(2) + `"`})
	if r.code != 200 || len(r.body) == 0 {
		t.Errorf("other etag: %d", r.code)
	}
}

func TestBundleRefusals(t *testing.T) {
	a := newAttest(t, goodFiles(1))
	h := withBundles(t, a)
	if r := h.getBundle(t, "GET", "nobody", nil); r.code != 404 || errCodeOf(t, r) != "unknown_host" {
		t.Errorf("unknown host: %d", r.code)
	}
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		r := h.getBundle(t, m, "h1", nil)
		if r.code != 405 || errCodeOf(t, r) != "method_not_allowed" || r.header.Get("Allow") != "GET, HEAD" {
			t.Errorf("%s: %d %v", m, r.code, r.header)
		}
	}
	if code, doc := h.do(t, "GET", "/v1/bundle", ""); code != 404 || errCode(doc) != "not_found" {
		t.Errorf("no host in path: %d %v", code, doc)
	}
	if code, doc := h.do(t, "GET", "/v1/bundle/h1/extra", ""); code != 404 || errCode(doc) != "unknown_host" {
		t.Errorf("extra path: %d %v", code, doc)
	}

	want503 := func(name, code string) {
		t.Helper()
		r := h.getBundle(t, "GET", "h1", nil)
		if r.code != 503 || errCodeOf(t, r) != code {
			t.Errorf("%s: %d %s", name, r.code, r.body)
		}
	}
	files := goodFiles(2)
	for _, drop := range []string{"bundle", "bundle.sig", "bundle.tar.gz"} {
		f := goodFiles(2)
		delete(f, drop)
		a.commit(f)
		want503("missing "+drop, "no_bundle")
	}
	for name, bad := range map[string]string{
		"empty":    "",
		"garbage":  "hello\n",
		"crlf":     strings.ReplaceAll(statementFor(c40(3), 1), "\n", "\r\n"),
		"no final": strings.TrimSuffix(statementFor(c40(3), 1), "\n"),
		"bad ref":  strings.Replace(statementFor(c40(3), 1), "refs/heads/main", "refs/heads/x", 1),
	} {
		f := goodFiles(2)
		f["bundle"] = bad
		a.commit(f)
		want503("malformed statement ("+name+")", "no_bundle")
	}
	// over-limit, with an injected limit
	a.commit(files)
	h.s.Bundles.Limits = bundle.Limits{Tarball: 100, Statement: bundle.MaxStatement, Signature: bundle.MaxSignature}
	want503("tarball over limit", "no_bundle")
	h.s.Bundles.Limits = bundle.Limits{Tarball: bundle.MaxTarball, Statement: bundle.MaxStatement, Signature: 10}
	want503("signature over limit", "no_bundle")
	h.s.Bundles.Limits = bundle.Limits{}
	if r := h.getBundle(t, "GET", "h1", nil); r.code != 200 {
		t.Errorf("recovered: %d", r.code)
	}
	// a repository without the branch
	h.s.Bundles.Repo = t.TempDir()
	testutil.RunGit(t, h.s.Bundles.Repo, "init", "-q", "--bare", ".")
	want503("no branch", "no_bundle")
	// no Bundles at all
	h.s.Bundles = nil
	want503("not configured", "no_bundle")
}

func TestBundleStaleMirror(t *testing.T) {
	a := newAttest(t, goodFiles(1))
	h := withBundles(t, a)
	upstream, _ := testutil.MakeUpstream(t)
	now := t0
	m := &gitmirror.Mirror{Repo: filepath.Join(t.TempDir(), "m.git"), Upstream: upstream, Now: func() time.Time { return now }}
	h.s.Bundles.Fresh = func() error { return m.Fresh(time.Hour) }
	// never fetched: stale
	if r := h.getBundle(t, "GET", "h1", nil); r.code != 503 || errCodeOf(t, r) != "stale_mirror" {
		t.Fatalf("never fetched: %d %s", r.code, r.body)
	}
	if err := m.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r := h.getBundle(t, "GET", "h1", nil); r.code != 200 {
		t.Fatalf("fresh: %d", r.code)
	}
	// two hours later with no fetch: stale, also for a conditional request that would have been a 304
	now = now.Add(2 * time.Hour)
	for _, hdr := range []map[string]string{nil, {"If-None-Match": `"` + c40(1) + `"`}} {
		if r := h.getBundle(t, "GET", "h1", hdr); r.code != 503 || errCodeOf(t, r) != "stale_mirror" {
			t.Errorf("stale %v: %d", hdr, r.code)
		}
	}
}

func TestBundleCacheFollowsTheBranch(t *testing.T) {
	a := newAttest(t, goodFiles(1))
	h := withBundles(t, a)
	r1 := h.getBundle(t, "GET", "h1", nil)
	r1b := h.getBundle(t, "GET", "h1", nil)
	if !bytes.Equal(r1.body, r1b.body) {
		t.Error("the same commit must be served from the cache (identical ciphertext)")
	}
	h.getBundle(t, "GET", "h2", nil)
	if h.s.Bundles.builds != 1 {
		t.Errorf("the archive was built %d times for two hosts, want once", h.s.Bundles.builds)
	}
	if n := h.s.Bundles.cachedEncrypted(); n != 2 {
		t.Fatalf("cache holds %d entries, want 2", n)
	}
	// the branch moves
	a.commit(goodFiles(2))
	r2 := h.getBundle(t, "GET", "h1", nil)
	if r2.code != 200 || r2.header.Get("ETag") != `"`+c40(2)+`"` || bytes.Equal(r1.body, r2.body) {
		t.Fatalf("after the move: %d %v", r2.code, r2.header)
	}
	_, data, _ := members(t, h.ids["h1"], r2.body)
	if string(data["bundle"]) != goodFiles(2)["bundle"] {
		t.Error("the new statement is not served")
	}
	// the old commit's entry for h2 was dropped, not kept alongside
	if n := h.s.Bundles.cachedEncrypted(); n != 1 {
		t.Errorf("cache holds %d entries after the move, want 1", n)
	}
	// the old ETag no longer matches
	if r := h.getBundle(t, "GET", "h1", map[string]string{"If-None-Match": `"` + c40(1) + `"`}); r.code != 200 {
		t.Errorf("old etag: %d", r.code)
	}
	// a branch that breaks stops being served, even though a cache entry exists for the old tip
	f := goodFiles(3)
	delete(f, "bundle.sig")
	a.commit(f)
	if r := h.getBundle(t, "GET", "h1", nil); r.code != 503 {
		t.Errorf("broken tip: %d", r.code)
	}
	if n := h.s.Bundles.cachedEncrypted(); n != 0 {
		t.Errorf("cache holds %d entries for a broken tip", n)
	}
}

func TestBundleRateLimited(t *testing.T) {
	h := withBundles(t, newAttest(t, goodFiles(1)))
	limited := 0
	for i := 0; i < 40; i++ {
		r := h.getBundleFrom(t, "198.51.100.7:1", "GET", "h1", map[string]string{"If-None-Match": "*"})
		if r.code == 429 {
			limited++
			if errCodeOf(t, r) != "rate_limited" || r.header.Get("Retry-After") == "" {
				t.Errorf("429 shape: %v", r.header)
			}
		}
	}
	if limited == 0 {
		t.Error("no request was rate limited")
	}
	if r := h.getBundleFrom(t, "198.51.100.8:1", "GET", "h1", nil); r.code != 200 {
		t.Errorf("another address: %d", r.code)
	}
}

func TestBundleNotModifiedNeedsNoFullLoad(t *testing.T) {
	h := withBundles(t, newAttest(t, goodFiles(1)))
	etag := `"` + c40(1) + `"`
	if r := h.getBundle(t, "GET", "h1", map[string]string{"If-None-Match": etag}); r.code != 304 {
		t.Fatalf("%d", r.code)
	}
	if h.s.Bundles.builds != 0 || h.s.Bundles.cur.archive != nil || h.s.Bundles.cachedEncrypted() != 0 {
		t.Error("a 304 built or encrypted something")
	}
	// the tarball can no longer be read, but the parsed statement of this tip answers
	h.s.Bundles.Limits = bundle.Limits{Tarball: 10, Statement: bundle.MaxStatement, Signature: bundle.MaxSignature}
	if r := h.getBundle(t, "GET", "h1", map[string]string{"If-None-Match": etag}); r.code != 304 {
		t.Errorf("warm 304: %d", r.code)
	}
	if r := h.getBundle(t, "GET", "h1", nil); r.code != 503 {
		t.Errorf("full request over the limit: %d", r.code)
	}
}

func TestBundleBadTimeIsNoBundle(t *testing.T) {
	a := newAttest(t, goodFiles(1))
	h := withBundles(t, a)
	for _, tm := range []int64{0, 8589934592} {
		f := goodFiles(2)
		f["bundle"] = statementFor(c40(2), tm)
		a.commit(f)
		if r := h.getBundle(t, "GET", "h1", nil); r.code != 503 || errCodeOf(t, r) != "no_bundle" {
			t.Errorf("time %d: %d", tm, r.code)
		}
	}
	f := goodFiles(2)
	f["bundle"] = statementFor(c40(2), 8589934591)
	a.commit(f)
	if r := h.getBundle(t, "GET", "h1", nil); r.code != 200 {
		t.Errorf("largest time: %d", r.code)
	}
}
