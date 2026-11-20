package httpsapi

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/KazuhaHub/infra-hub/internal/certs"
)

// fakeCerts is a CertSource over fixed data.
type fakeCerts struct {
	owners map[string]string
	p      certs.CertPayload
	err    error
}

func (f *fakeCerts) Owner(name string) (string, bool) { h, ok := f.owners[name]; return h, ok }
func (f *fakeCerts) Fetch(name string) (certs.CertPayload, error) {
	if f.err != nil {
		return certs.CertPayload{}, f.err
	}
	p := f.p
	p.Name = name
	return p, nil
}

type resp struct {
	code   int
	header http.Header
	body   []byte
}

func (h *testHub) get(t *testing.T, remote, method, path string, hdr map[string]string) resp {
	t.Helper()
	req, _ := http.NewRequest(method, "https://hub.example.org"+path, nil)
	req.RemoteAddr = remote
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := &recorder{header: http.Header{}, code: 200}
	h.s.Handler().ServeHTTP(rec, req)
	return resp{rec.code, rec.header, rec.body.Bytes()}
}

func certHub(t *testing.T) (*testHub, *fakeCerts) {
	t.Helper()
	h := newHub(t)
	f := &fakeCerts{owners: map[string]string{"a.example.org": "h1", "b.example.org": "h2"},
		p: certs.CertPayload{Fullchain: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", Privkey: "-----BEGIN PRIVATE KEY-----\nBBBB\n-----END PRIVATE KEY-----\n", NotAfter: "2027-01-01T00:00:00Z"}}
	h.s.Certs = f
	return h, f
}

func TestCertOwnerGetsTheSSHReplyEncrypted(t *testing.T) {
	h, f := certHub(t)
	r := h.get(t, "192.0.2.1:1", "GET", "/v1/cert/h1/a.example.org", nil)
	if r.code != 200 || r.header.Get("Content-Type") != "application/octet-stream" || r.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v", r.code, r.header)
	}
	if bytes.HasPrefix(r.body, []byte("-----BEGIN")) || bytes.Contains(r.body, []byte("PRIVATE KEY")) {
		t.Fatal("the body is armored or plain")
	}
	plain, err := age.Decrypt(bytes.NewReader(r.body), h.ids["h1"])
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(plain)
	want := `{"name":"a.example.org","fullchain":` + jsonStr(f.p.Fullchain) + `,"privkey":` + jsonStr(f.p.Privkey) + `,"not_after":"2027-01-01T00:00:00Z"}` + "\n"
	if string(got) != want {
		t.Fatalf("plaintext %q\nwant %q", got, want)
	}
	if _, err := age.Decrypt(bytes.NewReader(r.body), h.ids["h2"]); err == nil {
		t.Error("another host's key decrypts it")
	}
}

func jsonStr(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, "\n", `\n`), `"`, `\"`) + `"`
}

func TestCertRefusalsAreIdentical(t *testing.T) {
	h, _ := certHub(t)
	h.s.Certs.(*fakeCerts).owners["c.example.org"] = "nokey-owner"
	var first resp
	for i, path := range []string{
		"/v1/cert/h2/a.example.org",          // not the owner
		"/v1/cert/h1/zzz.example.org",        // unknown name
		"/v1/cert/nobody/a.example.org",      // unknown host
		"/v1/cert/nokey-owner/c.example.org", // owner without an age key
		"/v1/cert/h1/Bad_Name",               // not a name
		"/v1/cert/h1",                        // no name
		"/v1/cert/h1/a.example.org/x",        // too deep
	} {
		r := h.get(t, "192.0.2.1:1", "GET", path, nil)
		if r.code != 404 || errCodeOf(t, bundleResp{r.code, r.header, r.body}) != "not_found" {
			t.Fatalf("%s: %d %s", path, r.code, r.body)
		}
		if i == 0 {
			first = r
		} else if !bytes.Equal(r.body, first.body) {
			t.Errorf("%s: body differs: %s vs %s", path, r.body, first.body)
		}
	}
}

func TestCertNotServing(t *testing.T) {
	h, f := certHub(t)
	f.err = errors.New("certificate has less than 7 days left")
	r := h.get(t, "192.0.2.1:1", "GET", "/v1/cert/h1/a.example.org", nil)
	if r.code != 503 || errCodeOf(t, bundleResp{r.code, r.header, r.body}) != "not_serving" {
		t.Fatalf("%d %s", r.code, r.body)
	}
	if strings.Contains(string(r.body), "7 days") {
		t.Errorf("the reason leaks: %s", r.body)
	}
}

func TestCertNoProviderIsNotFound(t *testing.T) {
	h := newHub(t)
	if r := h.get(t, "192.0.2.1:1", "GET", "/v1/cert/h1/a.example.org", nil); r.code != 404 {
		t.Fatalf("%d", r.code)
	}
}

func TestCertRateLimitAndMethods(t *testing.T) {
	h, _ := certHub(t)
	for _, m := range []string{"POST", "PUT", "DELETE", "HEAD"} {
		r := h.get(t, "192.0.2.1:1", m, "/v1/cert/h1/a.example.org", nil)
		if r.code != 405 || r.header.Get("Allow") != "GET" {
			t.Errorf("%s: %d %v", m, r.code, r.header)
		}
	}
	for i := 0; i < 10; i++ {
		if r := h.get(t, "192.0.2.9:1", "GET", "/v1/cert/h1/a.example.org", nil); r.code != 200 {
			t.Fatalf("request %d: %d", i, r.code)
		}
	}
	r := h.get(t, "192.0.2.9:1", "GET", "/v1/cert/h1/a.example.org", nil)
	if r.code != 429 || errCodeOf(t, bundleResp{r.code, r.header, r.body}) != "rate_limited" {
		t.Fatalf("%d %s", r.code, r.body)
	}
	if r := h.get(t, "192.0.2.10:1", "GET", "/v1/cert/h1/a.example.org", nil); r.code != 200 {
		t.Errorf("another peer: %d", r.code)
	}
	h.now = h.now.Add(2 * time.Second) // 30 a minute: one token per 2 s
	if r := h.get(t, "192.0.2.9:1", "GET", "/v1/cert/h1/a.example.org", nil); r.code != 200 {
		t.Errorf("after refill: %d", r.code)
	}
}
