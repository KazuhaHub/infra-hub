package httpsapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/KazuhaHub/infra-hub/internal/iplists"
)

type fakeLists struct {
	known map[string]bool
	p     iplists.IPListPayload
	err   error
}

func (f *fakeLists) Has(name string) bool { return f.known[name] }
func (f *fakeLists) Serve(name string) (iplists.IPListPayload, error) {
	if f.err != nil {
		return iplists.IPListPayload{}, f.err
	}
	p := f.p
	p.Name = name
	return p, nil
}

func listHub(t *testing.T) (*testHub, *fakeLists) {
	t.Helper()
	h := newHub(t)
	f := &fakeLists{known: map[string]bool{"cdn": true, "other_1-x": true},
		p: iplists.IPListPayload{Version: "v1abc", Generated: "2026-11-20T00:00:00Z", CIDRs: []string{"11.1.0.0/24", "11.2.0.0/24"}, Warnings: []string{}}}
	h.s.IPLists = f
	return h, f
}

func TestIPListServed(t *testing.T) {
	h, f := listHub(t)
	r := h.get(t, "192.0.2.1:1", "GET", "/v1/iplist/cdn", nil)
	if r.code != 200 || r.header.Get("Content-Type") != "application/json" {
		t.Fatalf("%d %v", r.code, r.header)
	}
	p := f.p
	p.Name = "cdn"
	line, _ := json.Marshal(p)
	if string(r.body) != string(line)+"\n" {
		t.Fatalf("body %q, SSH line %q", r.body, line)
	}
	sum := sha256.Sum256(r.body)
	if etag := r.header.Get("ETag"); etag != `"`+hex.EncodeToString(sum[:])+`"` {
		t.Errorf("ETag %q", etag)
	}
	etag := r.header.Get("ETag")
	for _, inm := range []string{etag, "W/" + etag, `"x", ` + etag, "*"} {
		if r := h.get(t, "192.0.2.1:1", "GET", "/v1/iplist/cdn", map[string]string{"If-None-Match": inm}); r.code != 304 || len(r.body) != 0 {
			t.Errorf("If-None-Match %q: %d", inm, r.code)
		}
	}
	if r := h.get(t, "192.0.2.1:1", "GET", "/v1/iplist/cdn", map[string]string{"If-None-Match": `"other"`}); r.code != 200 {
		t.Errorf("other etag: %d", r.code)
	}
	f.p.CIDRs = append(f.p.CIDRs, "11.3.0.0/24")
	if r := h.get(t, "192.0.2.1:1", "GET", "/v1/iplist/cdn", map[string]string{"If-None-Match": etag}); r.code != 200 {
		t.Errorf("changed list: %d", r.code)
	}
}

func TestIPListHead(t *testing.T) {
	h, _ := listHub(t)
	get := h.get(t, "192.0.2.1:1", "GET", "/v1/iplist/cdn", nil)
	r := h.get(t, "192.0.2.1:1", "HEAD", "/v1/iplist/cdn", nil)
	if r.code != 200 || len(r.body) != 0 || r.header.Get("ETag") != get.header.Get("ETag") || r.header.Get("Content-Length") == "" {
		t.Fatalf("%d %v %q", r.code, r.header, r.body)
	}
}

func TestIPListErrors(t *testing.T) {
	h, f := listHub(t)
	for _, path := range []string{"/v1/iplist/nope", "/v1/iplist/", "/v1/iplist/CDN", "/v1/iplist/cdn/x", "/v1/iplist/" + strings.Repeat("a", 65), "/v1/iplist/..%2f"} {
		r := h.get(t, "192.0.2.1:1", "GET", path, nil)
		if r.code != 404 || errCodeOf(t, bundleResp{r.code, r.header, r.body}) != "not_found" {
			t.Errorf("%s: %d %s", path, r.code, r.body)
		}
	}
	if r := h.get(t, "192.0.2.1:1", "GET", "/v1/iplist/other_1-x", nil); r.code != 200 {
		t.Errorf("name with _ and -: %d", r.code)
	}
	f.err = errors.New("provider cdn: never delivered")
	r := h.get(t, "192.0.2.1:1", "GET", "/v1/iplist/cdn", nil)
	if r.code != 503 || errCodeOf(t, bundleResp{r.code, r.header, r.body}) != "not_serving" || strings.Contains(string(r.body), "provider") {
		t.Errorf("not serving: %d %s", r.code, r.body)
	}
	for _, m := range []string{"POST", "PUT", "DELETE"} {
		if r := h.get(t, "192.0.2.1:1", m, "/v1/iplist/cdn", nil); r.code != 405 || r.header.Get("Allow") != "GET, HEAD" {
			t.Errorf("%s: %d", m, r.code)
		}
	}
	h2 := newHub(t)
	if r := h2.get(t, "192.0.2.1:1", "GET", "/v1/iplist/cdn", nil); r.code != 404 {
		t.Errorf("no provider: %d", r.code)
	}
}

func TestIPListRateLimit(t *testing.T) {
	h, _ := listHub(t)
	for i := 0; i < 20; i++ {
		if r := h.get(t, "192.0.2.9:1", "GET", "/v1/iplist/cdn", nil); r.code != 200 {
			t.Fatalf("request %d: %d", i, r.code)
		}
	}
	r := h.get(t, "192.0.2.9:1", "GET", "/v1/iplist/cdn", nil)
	if r.code != 429 || errCodeOf(t, bundleResp{r.code, r.header, r.body}) != "rate_limited" {
		t.Fatalf("%d %s", r.code, r.body)
	}
	if r := h.get(t, "192.0.2.10:1", "GET", "/v1/iplist/cdn", nil); r.code != 200 {
		t.Errorf("another peer: %d", r.code)
	}
}
