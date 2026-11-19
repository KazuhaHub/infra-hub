package iplists

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "iplists", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func realSources(t *testing.T) map[string]IPSource {
	t.Helper()
	var s map[string]IPSource
	if err := json.Unmarshal(fixture(t, "sources.json"), &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestValidationVectors(t *testing.T) {
	var vectors []struct {
		In  string  `json:"in"`
		Out *string `json:"out"`
	}
	if err := json.Unmarshal(fixture(t, "validation-vectors.json"), &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		p, err := NormalizeCIDR(v.In)
		switch {
		case v.Out == nil && err == nil:
			t.Errorf("%q accepted as %s", v.In, p)
		case v.Out != nil && err != nil:
			t.Errorf("%q refused: %v", v.In, err)
		case v.Out != nil && p.String() != *v.Out:
			t.Errorf("%q -> %s, want %s", v.In, p, *v.Out)
		}
	}
}

func TestNormalizeAllSortsDedupesAndRefusesAnyBadEntry(t *testing.T) {
	got, err := NormalizeAll([]string{"2606:4700::/32", "104.16.0.0/13", "104.16.0.1/13", "104.16.0.0/12", "8.8.8.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"8.8.8.0/24", "104.16.0.0/12", "104.16.0.0/13", "2606:4700::/32"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
	if _, err := NormalizeAll([]string{"8.8.8.0/24", "10.0.0.0/8"}); err == nil {
		t.Fatal("a private entry was accepted with good ones")
	}
	if _, err := NormalizeAll(nil); err == nil {
		t.Fatal("empty accepted")
	}
}

func TestParseRealFixtures(t *testing.T) {
	src := realSources(t)
	cases := []struct {
		provider, file string
		count          int
		has, hasNot    []string
	}{
		{"cloudflare", "cloudflare.json", 22, []string{"173.245.48.0/20", "2c0f:f248::/32"}, nil},
		{"fastly", "fastly.json", 24, []string{"151.101.0.0/16", "2a04:4e42::/31"}, nil},
		{"github_hooks", "github_meta.json", 9, []string{"192.30.252.0/22", "2606:50c0::/32"}, []string{"140.82.112.0/22"}},
		{"google", "google.json", 0, []string{"8.8.8.0/24"}, nil},
		{"aws_cloudfront", "aws.json", 0, nil, nil},
	}
	for _, c := range cases {
		got, err := ParseSource(src[c.provider], fixture(t, c.file))
		if err != nil {
			t.Fatalf("%s: %v", c.provider, err)
		}
		if c.count > 0 && len(got) != c.count {
			t.Errorf("%s: %d entries, want %d", c.provider, len(got), c.count)
		}
		if len(got) < 9 {
			t.Errorf("%s: only %d entries", c.provider, len(got))
		}
		set := map[string]bool{}
		for _, g := range got {
			set[g] = true
		}
		for _, h := range c.has {
			if !set[h] {
				t.Errorf("%s: %s missing", c.provider, h)
			}
		}
		for _, h := range c.hasNot {
			if set[h] {
				t.Errorf("%s: %s present", c.provider, h)
			}
		}
	}
}

func TestAWSSelectsOnlyCloudFront(t *testing.T) {
	got, err := ParseSource(realSources(t)["aws_cloudfront"], fixture(t, "aws.json"))
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Prefixes []struct {
			IP      string `json:"ip_prefix"`
			Service string `json:"service"`
		} `json:"prefixes"`
		V6 []struct {
			IP      string `json:"ipv6_prefix"`
			Service string `json:"service"`
		} `json:"ipv6_prefixes"`
	}
	json.Unmarshal(fixture(t, "aws.json"), &raw)
	want := map[string]bool{}
	other := map[string]bool{}
	for _, p := range raw.Prefixes {
		if p.Service == "CLOUDFRONT" || p.Service == "CLOUDFRONT_ORIGIN_FACING" {
			want[p.IP] = true
		} else {
			other[p.IP] = true
		}
	}
	for _, p := range raw.V6 {
		if p.Service == "CLOUDFRONT" || p.Service == "CLOUDFRONT_ORIGIN_FACING" {
			want[p.IP] = true
		}
	}
	norm, err := NormalizeAll(keys(want))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, norm) {
		t.Fatalf("got %d entries, want %d", len(got), len(norm))
	}
	for _, g := range got {
		if other[g] && !want[g] {
			t.Errorf("%s is not CloudFront", g)
		}
	}
	hasV6 := false
	for _, g := range got {
		hasV6 = hasV6 || strings.Contains(g, ":")
	}
	if !hasV6 {
		t.Error("no IPv6 entries")
	}
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestParseLinesFormat(t *testing.T) {
	src := IPSource{URL: "https://x", Format: "lines"}
	got, err := ParseSource(src, fixture(t, "cloudflare-lines.txt")) // no trailing newline on the last line
	if err != nil || len(got) != 22 {
		t.Fatalf("%d %v", len(got), err)
	}
	got, err = ParseSource(src, []byte("# header\n\n  1.1.1.0/24  # one\r\n2606:4700::/32\n\t\n"))
	if err != nil || !reflect.DeepEqual(got, []string{"1.1.1.0/24", "2606:4700::/32"}) {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"", "# only a comment\n", "1.1.1.0/24\nnot-an-ip\n", "1.1.1.0/24\n10.0.0.0/8\n", "1.1.1.0/24\x00\n", "<html>blocked</html>"} {
		if _, err := ParseSource(src, []byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestParseJSONRefusesWhatDoesNotFit(t *testing.T) {
	src := IPSource{URL: "https://x", Format: "json", Select: []string{"a", "b"}}
	if _, err := ParseSource(src, []byte(`{"a":["1.1.1.0/24"],"b":["2606:4700::/32"]}`)); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{
		"not json":          `<html>`,
		"trailing":          `{"a":["1.1.1.0/24"],"b":["2606:4700::/32"]} {}`,
		"selector no match": `{"a":["1.1.1.0/24"]}`,
		"empty array":       `{"a":["1.1.1.0/24"],"b":[]}`,
		"not strings":       `{"a":["1.1.1.0/24"],"b":[1,2]}`,
		"a string":          `{"a":"1.1.1.0/24","b":["2606:4700::/32"]}`,
		"a private entry":   `{"a":["1.1.1.0/24","192.168.0.0/16"],"b":["2606:4700::/32"]}`,
		"everything":        `{"a":["0.0.0.0/0"],"b":["2606:4700::/32"]}`,
	} {
		if _, err := ParseSource(src, []byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestEveryShippedSourceIsAValidConfig(t *testing.T) {
	for name, s := range realSources(t) {
		if err := s.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := []IPSource{
		{URL: "http://x", Format: "lines"}, {URL: "https://x", Format: "xml"}, {URL: "https://x", Format: "json"},
		{URL: "https://x", Format: "json", Select: []string{"a["}}, {URL: "https://x", Format: "lines", Select: []string{"a"}},
		{URL: "https://x", Format: "lines", MaxBytes: LargestMaxBytes + 1},
	}
	for _, s := range bad {
		if s.Validate() == nil {
			t.Errorf("accepted %+v", s)
		}
	}
}

// fakeProvider is an HTTPS-less test server whose answer the test controls.
type fakeProvider struct {
	mu     sync.Mutex
	status int
	body   string
	delay  time.Duration
	srv    *httptest.Server
}

func newFakeProvider(t *testing.T, cidrs ...string) *fakeProvider {
	f := &fakeProvider{status: 200}
	f.set(cidrs...)
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		status, body, delay := f.status, f.body, f.delay
		f.mu.Unlock()
		time.Sleep(delay)
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeProvider) set(cidrs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.body = strings.Join(cidrs, "\n") + "\n"
}

func (f *fakeProvider) fail(status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.body = status, body
}

func (f *fakeProvider) ok() { f.mu.Lock(); f.status = 200; f.mu.Unlock() }

type ipClock struct{ t time.Time }

func (c *ipClock) now() time.Time { return c.t }

func newIPTestManager(t *testing.T, f *fakeProvider, manual ...string) (*IPManager, *ipClock) {
	t.Helper()
	clk := &ipClock{t: time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)}
	return &IPManager{
		Dir:     filepath.Join(t.TempDir(), "iplists"),
		Sources: map[string]IPSource{"cdn": {URL: f.srv.URL, Format: "lines"}},
		Lists:   map[string]IPList{"cdn": {Providers: []string{"cdn"}, Manual: manual, Hosts: []string{"host-a"}}},
		Now:     clk.now,
		Client:  &http.Client{Timeout: 300 * time.Millisecond},
	}, clk
}

// ranges makes n distinct public /24s.
func ranges(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("11.%d.0.0/24", i+1)
	}
	return out
}

func (m *IPManager) state() ProviderState { st, _ := loadProvider(m.path("cdn")); return st }

func TestFirstRefreshStoresTheList(t *testing.T) {
	f := newFakeProvider(t, ranges(10)...)
	m, clk := newIPTestManager(t, f)
	m.Refresh(context.Background(), "cdn")
	st := m.state()
	if len(st.CIDRs) != 10 || st.Held || st.LastError != "" || !st.LastSuccess.Equal(clk.t) || !st.LastChange.Equal(clk.t) {
		t.Fatalf("%+v", st)
	}
	if !st.NextAttempt.Equal(clk.t.Add(6 * time.Hour)) {
		t.Fatalf("next attempt %v", st.NextAttempt)
	}
}

func TestSmallChangeIsAppliedAndChangeTimeMoves(t *testing.T) {
	f := newFakeProvider(t, ranges(10)...)
	m, clk := newIPTestManager(t, f)
	m.Refresh(context.Background(), "cdn")
	clk.t = clk.t.Add(6 * time.Hour)
	f.set(append(ranges(10)[1:], "12.0.0.0/24", "12.1.0.0/24")...) // 1 removed, 2 added
	m.Refresh(context.Background(), "cdn")
	st := m.state()
	if st.Held || len(st.CIDRs) != 11 || !st.LastChange.Equal(clk.t) {
		t.Fatalf("%+v", st)
	}
	// the same answer again is not a change
	before := st.LastChange
	clk.t = clk.t.Add(6 * time.Hour)
	m.Refresh(context.Background(), "cdn")
	if st = m.state(); !st.LastChange.Equal(before) || !st.LastSuccess.Equal(clk.t) {
		t.Fatalf("%+v", st)
	}
}

func TestChangeGuardHoldsBigRemovalAndBigAddition(t *testing.T) {
	cases := []struct {
		name string
		next []string
		held bool
	}{
		{"remove exactly 30%", ranges(10)[3:], false},
		{"remove more than 30%", ranges(10)[4:], true},
		{"add exactly 50%", append(ranges(10), ranges(15)[10:]...), false},
		{"add more than 50%", append(ranges(10), ranges(16)[10:]...), true},
		{"replace everything", ranges(30)[20:], true},
	}
	for _, c := range cases {
		f := newFakeProvider(t, ranges(10)...)
		m, clk := newIPTestManager(t, f)
		m.Refresh(context.Background(), "cdn")
		clk.t = clk.t.Add(6 * time.Hour)
		f.set(c.next...)
		m.Refresh(context.Background(), "cdn")
		st := m.state()
		if st.Held != c.held {
			t.Errorf("%s: held=%v (%s)", c.name, st.Held, st.HeldReason)
		}
		if c.held && (len(st.CIDRs) != 10 || len(st.Pending) != len(c.next) || st.HeldReason == "") {
			t.Errorf("%s: the old list must still be served: %+v", c.name, st)
		}
		if !c.held && len(st.CIDRs) != len(c.next) {
			t.Errorf("%s: not applied", c.name)
		}
	}
}

func TestHeldUpdateIsAppliedOnlyByAccept(t *testing.T) {
	f := newFakeProvider(t, ranges(10)...)
	m, clk := newIPTestManager(t, f)
	m.Refresh(context.Background(), "cdn")
	f.set(ranges(30)[20:]...)
	clk.t = clk.t.Add(6 * time.Hour)
	m.Refresh(context.Background(), "cdn")
	if !m.state().Held {
		t.Fatal("not held")
	}
	// Serving continues with the old list while held, and again after more refreshes.
	for i := 0; i < 3; i++ {
		clk.t = clk.t.Add(6 * time.Hour)
		m.Refresh(context.Background(), "cdn")
		p, err := m.Serve("cdn")
		if err != nil || len(p.CIDRs) != 10 || p.CIDRs[0] != "11.1.0.0/24" {
			t.Fatalf("held list is served wrongly: %v %v", p.CIDRs, err)
		}
	}
	// A request that was made for another update does nothing.
	os.MkdirAll(m.acceptDir(), 0o700)
	os.WriteFile(filepath.Join(m.acceptDir(), "cdn"), []byte(ListVersion(ranges(5))+"\n"), 0o600)
	m.applyAccepts()
	if !m.state().Held {
		t.Fatal("a stale accept request was applied")
	}
	if _, err := os.Stat(filepath.Join(m.acceptDir(), "cdn")); err == nil {
		t.Fatal("request not removed")
	}
	// The real command.
	st, err := RequestAccept(m.Dir, "cdn")
	if err != nil || len(st.Pending) != 10 {
		t.Fatal(err)
	}
	if !m.state().Held {
		t.Fatal("the command itself must not change the provider file")
	}
	m.applyAccepts()
	st = m.state()
	if st.Held || len(st.Pending) != 0 || st.CIDRs[0] != "11.21.0.0/24" || !st.LastChange.Equal(clk.t) {
		t.Fatalf("%+v", st)
	}
	if _, err := RequestAccept(m.Dir, "cdn"); err == nil {
		t.Fatal("accept with nothing held")
	}
}

func TestAcceptRefusesAnUnknownOrOddProviderName(t *testing.T) {
	if _, err := RequestAccept(t.TempDir(), "../x"); err == nil {
		t.Fatal("path accepted")
	}
	if err := AcceptReport(t.TempDir(), map[string]IPSource{}, "nope", &bytes.Buffer{}); err == nil {
		t.Fatal("unknown provider accepted")
	}
}

func TestAcceptCommandPrintsTheChange(t *testing.T) {
	f := newFakeProvider(t, ranges(10)...)
	m, clk := newIPTestManager(t, f)
	m.Refresh(context.Background(), "cdn")
	f.set(ranges(30)[20:]...)
	clk.t = clk.t.Add(time.Hour)
	m.Refresh(context.Background(), "cdn")
	var out bytes.Buffer
	if err := AcceptReport(m.Dir, m.Sources, "cdn", &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"10 entries by 10", "- 11.1.0.0/24", "+ 11.21.0.0/24", "10 removed, 10 added"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
}

func TestHoldClearsWhenTheProviderGoesBack(t *testing.T) {
	f := newFakeProvider(t, ranges(10)...)
	m, clk := newIPTestManager(t, f)
	m.Refresh(context.Background(), "cdn")
	f.set(ranges(30)[20:]...)
	clk.t = clk.t.Add(time.Hour)
	m.Refresh(context.Background(), "cdn")
	f.set(ranges(10)...) // the glitch is over
	clk.t = clk.t.Add(time.Hour)
	m.Refresh(context.Background(), "cdn")
	if st := m.state(); st.Held || st.Pending != nil || st.HeldReason != "" {
		t.Fatalf("%+v", st)
	}
}

func TestLastGoodListSurvivesEveryKindOfFailure(t *testing.T) {
	big := strings.Repeat("# padding\n", DefaultMaxBytes/10+10)
	cases := map[string]func(f *fakeProvider){
		"http 500":        func(f *fakeProvider) { f.fail(500, "oops") },
		"http 404":        func(f *fakeProvider) { f.fail(404, "") },
		"html":            func(f *fakeProvider) { f.fail(200, "<html>captcha</html>") },
		"empty":           func(f *fakeProvider) { f.fail(200, "") },
		"only comments":   func(f *fakeProvider) { f.fail(200, "# nothing\n") },
		"everything":      func(f *fakeProvider) { f.fail(200, "0.0.0.0/0\n") },
		"one private":     func(f *fakeProvider) { f.fail(200, "11.1.0.0/24\n10.0.0.0/8\n") },
		"too large":       func(f *fakeProvider) { f.fail(200, big+"11.1.0.0/24\n") },
		"too slow":        func(f *fakeProvider) { f.delay = time.Second },
		"connection lost": func(f *fakeProvider) { f.srv.CloseClientConnections(); f.srv.Close() },
	}
	for name, breakIt := range cases {
		f := newFakeProvider(t, ranges(10)...)
		m, clk := newIPTestManager(t, f)
		m.Refresh(context.Background(), "cdn")
		good := m.state()
		breakIt(f)
		clk.t = clk.t.Add(6 * time.Hour)
		m.Refresh(context.Background(), "cdn")
		st := m.state()
		if !reflect.DeepEqual(st.CIDRs, good.CIDRs) || st.LastError == "" || st.Failures != 1 || !st.LastSuccess.Equal(good.LastSuccess) {
			t.Errorf("%s: %+v", name, st)
		}
		if p, err := m.Serve("cdn"); err != nil || len(p.CIDRs) != 10 {
			t.Errorf("%s: not served from the last good list: %v", name, err)
		}
	}
}

func TestBackoffGrowsAndSuccessResetsIt(t *testing.T) {
	want := []time.Duration{15 * time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour, 4 * time.Hour, 6 * time.Hour, 6 * time.Hour}
	for i, w := range want {
		if got := ipBackoff(i + 1); got != w {
			t.Errorf("failure %d: %v, want %v", i+1, got, w)
		}
	}
	f := newFakeProvider(t, ranges(10)...)
	m, clk := newIPTestManager(t, f)
	f.fail(503, "")
	m.Refresh(context.Background(), "cdn")
	m.Refresh(context.Background(), "cdn")
	st := m.state()
	if st.Failures != 2 || !st.NextAttempt.Equal(clk.t.Add(30*time.Minute)) {
		t.Fatalf("%+v", st)
	}
	// a provider that has never delivered cannot make a list
	if _, err := m.Serve("cdn"); err == nil {
		t.Fatal("served a list with no data")
	}
	f.set(ranges(10)...)
	f.ok()
	m.Refresh(context.Background(), "cdn")
	if st = m.state(); st.Failures != 0 || st.LastError != "" || len(st.CIDRs) != 10 {
		t.Fatalf("%+v", st)
	}
}

func TestRunOnceRefreshesOnlyDueProviders(t *testing.T) {
	var hits int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		fmt.Fprint(w, strings.Join(ranges(10), "\n"))
	}))
	defer srv.Close()
	clk := &ipClock{t: time.Now()}
	m := &IPManager{Dir: t.TempDir(), Sources: map[string]IPSource{"cdn": {URL: srv.URL, Format: "lines"}, "unused": {URL: srv.URL, Format: "lines"}},
		Lists: map[string]IPList{"l": {Providers: []string{"cdn"}}}, Now: clk.now}
	m.RunOnce(context.Background())
	m.RunOnce(context.Background())
	clk.t = clk.t.Add(5*time.Hour + 59*time.Minute)
	m.RunOnce(context.Background())
	if hits != 1 {
		t.Fatalf("%d downloads before the interval, want 1 (and none for a provider no list uses)", hits)
	}
	clk.t = clk.t.Add(2 * time.Minute)
	m.RunOnce(context.Background())
	if hits != 2 {
		t.Fatalf("%d downloads after the interval", hits)
	}
}

func TestRedirectToPlainHTTPIsRefused(t *testing.T) {
	plain := newFakeProvider(t, ranges(5)...)
	redir := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, plain.srv.URL, 302) }))
	defer redir.Close()
	m := &IPManager{}
	c := m.client()
	c.Transport = redir.Client().Transport
	m.Client = c
	if _, err := m.download(context.Background(), IPSource{URL: redir.URL, Format: "lines"}); err == nil {
		t.Fatal("followed a redirect to http")
	}
}

func TestServeUnionsProvidersAndManualEntries(t *testing.T) {
	f := newFakeProvider(t, "104.16.0.0/13", "2606:4700::/32")
	m, _ := newIPTestManager(t, f, "203.0.114.0/24", "104.16.0.5/13")
	m.Refresh(context.Background(), "cdn")
	p, err := m.Serve("cdn")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.CIDRs, []string{"104.16.0.0/13", "203.0.114.0/24", "2606:4700::/32"}) || p.Version != ListVersion(p.CIDRs) || p.Name != "cdn" {
		t.Fatalf("%+v", p)
	}
	if _, err := time.Parse(time.RFC3339, p.Generated); err != nil {
		t.Fatal(err)
	}
	// manual entries alone are enough for a list without providers
	m2 := &IPManager{Dir: t.TempDir(), Lists: map[string]IPList{"m": {Manual: []string{"203.0.114.0/24"}}}}
	if p, err := m2.Serve("m"); err != nil || len(p.CIDRs) != 1 {
		t.Fatalf("%v %v", p, err)
	}
	if _, err := m.Serve("other"); err == nil {
		t.Fatal("unknown list served")
	}
}

func TestStatusShowsProvidersListsAndHeld(t *testing.T) {
	f := newFakeProvider(t, ranges(10)...)
	m, clk := newIPTestManager(t, f, "203.0.114.0/24")
	m.Refresh(context.Background(), "cdn")
	f.fail(500, "")
	clk.t = clk.t.Add(time.Hour)
	m.Refresh(context.Background(), "cdn")
	st := m.Status()
	p := st.Providers["cdn"]
	if p.Count != 10 || p.LastSuccess == nil || p.LastChange == nil || p.LastError != "HTTP 500" || p.Held || p.Failures != 1 {
		t.Fatalf("%+v", p)
	}
	if l := st.Lists["cdn"]; l.Entries != 11 || l.Manual != 1 || l.Version == "" || !reflect.DeepEqual(l.Hosts, []string{"host-a"}) {
		t.Fatalf("%+v", l)
	}
	f.set(ranges(10)...)
	f.ok()
	f.set(ranges(30)[20:]...)
	m.Refresh(context.Background(), "cdn")
	p = m.Status().Providers["cdn"]
	if !p.Held || p.Pending != 10 || !strings.Contains(p.HeldReason, "remove") || p.LastError != "" {
		t.Fatalf("%+v", p)
	}
	// as the hub's status command prints it
	var buf bytes.Buffer
	json.NewEncoder(&buf).Encode(m.Status())
	if !strings.Contains(buf.String(), `"held":true`) {
		t.Fatalf("%s", buf.String())
	}
}

// The golden reply is what the hub sends for the Cloudflare fixture; the client's tests (the pull script)
// parse the same file, so the two implementations are checked against each other. UPDATE_GOLDEN=1 rewrites it.
func TestGoldenReplyForTheCloudflareFixture(t *testing.T) {
	cidrs, err := ParseSource(realSources(t)["cloudflare"], fixture(t, "cloudflare.json"))
	if err != nil {
		t.Fatal(err)
	}
	line, _ := json.Marshal(IPListPayload{Name: "cloudflare", Version: ListVersion(cidrs), Generated: "2026-11-18T12:00:00Z", CIDRs: cidrs, Warnings: []string{}})
	line = append(line, '\n')
	path := filepath.Join("..", "..", "testdata", "iplists", "reply-cloudflare.json")
	if os.Getenv("UPDATE_GOLDEN") != "" {
		os.WriteFile(path, line, 0o644)
	}
	if got := fixture(t, "reply-cloudflare.json"); !bytes.Equal(got, line) {
		t.Fatalf("golden reply differs; run UPDATE_GOLDEN=1 go test -run Golden\n%s\n%s", got, line)
	}
}

func TestOneWidePrefixIsHeldByTheAddressSpaceGuard(t *testing.T) {
	f := newFakeProvider(t, ranges(30)...)
	m, clk := newIPTestManager(t, f)
	m.Refresh(context.Background(), "cdn")
	clk.t = clk.t.Add(6 * time.Hour)
	f.set(append(ranges(30), "45.0.0.0/8")...) // one more entry, 65536 times the space
	m.Refresh(context.Background(), "cdn")
	st := m.state()
	if !st.Held || !strings.Contains(st.HeldReason, "address space") || len(st.CIDRs) != 30 {
		t.Fatalf("%+v", st)
	}
}

func TestListsThatCoverTooMuchOrAreTooLongAreRefused(t *testing.T) {
	var wide []string
	for i := 12; i < 12+80; i++ { // 80 public /8s: 1.3 billion addresses
		wide = append(wide, fmt.Sprintf("%d.0.0.0/8", i))
	}
	if _, err := NormalizeAll(wide); err == nil {
		t.Fatal("a list covering a third of IPv4 was accepted")
	}
	if _, err := NormalizeAll(wide[:20]); err != nil {
		t.Fatalf("20 /8s are under the cap: %v", err)
	}
	var many []string
	for i := 0; i < MaxEntries+1; i++ {
		many = append(many, fmt.Sprintf("%d.%d.%d.0/24", 11+i/65536, i/256%256, i%256))
	}
	if _, err := NormalizeAll(many); err == nil {
		t.Fatal("too many entries accepted")
	}
}

func TestAcceptRefusesASymlinkedRequestDirectory(t *testing.T) {
	f := newFakeProvider(t, ranges(10)...)
	m, clk := newIPTestManager(t, f)
	m.Refresh(context.Background(), "cdn")
	f.set(ranges(30)[20:]...)
	clk.t = clk.t.Add(time.Hour)
	m.Refresh(context.Background(), "cdn")
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(m.Dir, "accept")); err != nil {
		t.Fatal(err)
	}
	if _, err := RequestAccept(m.Dir, "cdn"); err == nil {
		t.Fatal("followed a symlink")
	}
	if es, _ := os.ReadDir(target); len(es) != 0 {
		t.Fatal("wrote through the symlink")
	}
}

func TestCorruptOrUnreadableStateIsAnErrorNotAnEmptyOrFirstList(t *testing.T) {
	f := newFakeProvider(t, ranges(10)...)
	m, clk := newIPTestManager(t, f)
	m.Refresh(context.Background(), "cdn")
	path := m.path("cdn")
	good, _ := os.ReadFile(path)
	for name, content := range map[string]string{"garbage": "{not json", "empty file": ""} {
		os.WriteFile(path, []byte(content), 0o600)
		clk.t = clk.t.Add(7 * time.Hour)
		m.RunOnce(context.Background())
		m.Refresh(context.Background(), "cdn") // even when asked directly
		if got, _ := os.ReadFile(path); string(got) != content {
			t.Errorf("%s: the state file was overwritten (a corrupt state taken as a first list)", name)
		}
		if _, err := m.Serve("cdn"); err == nil {
			t.Errorf("%s: served", name)
		}
		st := m.Status()
		if !st.Providers["cdn"].Failing || st.Providers["cdn"].StateError == "" || len(st.Lists["cdn"].Warnings) == 0 {
			t.Errorf("%s: %+v", name, st)
		}
	}
	os.Remove(path)
	os.Mkdir(path, 0o700) // a directory in its place is unreadable too
	if _, err := m.Serve("cdn"); err == nil {
		t.Error("a directory was served")
	}
	os.Remove(path)
	os.WriteFile(path, good, 0o600)
	if _, err := m.Serve("cdn"); err != nil {
		t.Fatal(err)
	}
}

func TestWarningsTravelWithTheList(t *testing.T) {
	f := newFakeProvider(t, ranges(10)...)
	m, clk := newIPTestManager(t, f)
	m.Refresh(context.Background(), "cdn")
	if p, _ := m.Serve("cdn"); len(p.Warnings) != 0 || p.Warnings == nil {
		t.Fatalf("a healthy list has no warnings: %#v", p.Warnings)
	}
	f.fail(500, "")
	for i := 0; i < 3; i++ {
		clk.t = clk.t.Add(30 * time.Minute)
		m.Refresh(context.Background(), "cdn")
	}
	p, _ := m.Serve("cdn")
	if len(p.Warnings) != 1 || !strings.HasPrefix(p.Warnings[0], "failing:cdn 3 attempts") {
		t.Fatalf("%v", p.Warnings)
	}
	clk.t = clk.t.Add(25 * time.Hour)
	p, _ = m.Serve("cdn")
	if len(p.Warnings) != 2 || !strings.Contains(strings.Join(p.Warnings, "|"), "older than 24h") {
		t.Fatalf("%v", p.Warnings)
	}
	f.ok()
	f.set(ranges(30)[20:]...)
	m.Refresh(context.Background(), "cdn")
	p, _ = m.Serve("cdn")
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "update held") {
		t.Fatalf("%v", p.Warnings)
	}
	for _, w := range p.Warnings {
		if w != printable(w) {
			t.Errorf("not plain ASCII: %q", w)
		}
	}
	if st := m.Status(); !st.Providers["cdn"].Held || len(st.Lists["cdn"].Warnings) != 1 {
		t.Fatalf("%+v", st)
	}
}

func TestSpaceOnlyRemovalIsHeld(t *testing.T) {
	// 9 small entries and one big one: removing the big one is 1 of 10 entries but most of the space.
	old := append(ranges(9), "45.0.0.0/16")
	f := newFakeProvider(t, old...)
	m, clk := newIPTestManager(t, f)
	m.Refresh(context.Background(), "cdn")
	clk.t = clk.t.Add(time.Hour)
	f.set(ranges(9)...)
	m.Refresh(context.Background(), "cdn")
	st := m.state()
	if !st.Held || !strings.Contains(st.HeldReason, "remove more than 30% of the IPv4 address space") {
		t.Fatalf("%+v", st)
	}
}

func TestIPv6TotalCapAndTheListVectors(t *testing.T) {
	var vectors []struct {
		Name  string `json:"name"`
		Kind  string `json:"kind"`
		Count int    `json:"count"`
		OK    bool   `json:"ok"`
	}
	if err := json.Unmarshal(fixture(t, "validation-list-vectors.json"), &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		var entries []string
		for i := 0; i < v.Count; i++ {
			switch v.Kind {
			case "v6_slash16": // first hextet 0x4000 upward
				entries = append(entries, fmt.Sprintf("%x::/16", 0x4000+i))
			case "v6_slash32":
				entries = append(entries, fmt.Sprintf("2606:%x::/32", 0x4700+i))
			case "v4_slash8":
				entries = append(entries, fmt.Sprintf("%d.0.0.0/8", 12+i))
			case "v4_slash24":
				entries = append(entries, fmt.Sprintf("%d.%d.%d.0/24", 11+i/65536, i/256%256, i%256))
			default:
				t.Fatal(v.Kind)
			}
		}
		if _, err := NormalizeAll(entries); (err == nil) != v.OK {
			t.Errorf("%s: err=%v, want ok=%v", v.Name, err, v.OK)
		}
	}
}

func TestHistoryAppendRotateAndRead(t *testing.T) {
	dir := t.TempDir()
	if got := ReadHistory(dir, "cf", 0); len(got) != 0 || got == nil {
		t.Fatalf("a list without history reads as an empty list: %#v", got)
	}
	for i := 0; i < HistoryMax+HistorySlack; i++ {
		if err := AppendHistory(dir, "cf", HistoryEntry{Time: "t", Event: "provider update", Version: fmt.Sprint(i)}); err != nil {
			t.Fatal(err)
		}
	}
	all := ReadHistory(dir, "cf", 0)
	if len(all) != HistoryMax+HistorySlack {
		t.Fatalf("%d entries before rotation", len(all))
	}
	AppendHistory(dir, "cf", HistoryEntry{Time: "t", Event: "accept", Version: "last"}) // one over: rotate to the newest HistoryMax
	all = ReadHistory(dir, "cf", 0)
	if len(all) != HistoryMax || all[len(all)-1].Version != "last" || all[0].Version != fmt.Sprint(HistorySlack+1) {
		t.Fatalf("%d entries, first %q last %q", len(all), all[0].Version, all[len(all)-1].Version)
	}
	if got := ReadHistory(dir, "cf", 3); len(got) != 3 || got[2].Version != "last" || got[0].Version != fmt.Sprint(HistoryMax+HistorySlack-2) {
		t.Fatalf("%+v", got)
	}
	// no temp files are left by the rotation, other lists are separate, and a damaged line is skipped
	entries, _ := os.ReadDir(filepath.Join(dir, "history"))
	if len(entries) != 1 {
		t.Fatalf("%v", entries)
	}
	f, _ := os.OpenFile(historyPath(dir, "cf"), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("{torn\n")
	f.Close()
	if got := ReadHistory(dir, "cf", 0); len(got) != HistoryMax {
		t.Fatalf("%d", len(got))
	}
	if len(ReadHistory(dir, "other", 0)) != 0 {
		t.Fatal("lists share a history")
	}
}

func TestHistoryRecordsFirstFetchUpdateHeldAndAccept(t *testing.T) {
	f := newFakeProvider(t, ranges(10)...)
	m, clk := newIPTestManager(t, f, "203.0.114.0/24")
	hist := func() []HistoryEntry { return ReadHistory(m.Dir, "cdn", 0) }
	m.Refresh(context.Background(), "cdn")
	h := hist()
	if len(h) != 1 || h[0].Event != "first fetch" || h[0].PreviousVersion != "" || h[0].AddedCount != 11 || h[0].CountAfter != 11 || h[0].Provider != "cdn" {
		t.Fatalf("%+v", h)
	}
	first := h[0].Version
	if p, _ := m.Serve("cdn"); p.Version != first {
		t.Fatal("the history's version is not the served one")
	}
	// no change, no entry
	clk.t = clk.t.Add(6 * time.Hour)
	m.Refresh(context.Background(), "cdn")
	if len(hist()) != 1 {
		t.Fatalf("%+v", hist())
	}
	// a small change
	f.set(append(ranges(10)[1:], "12.0.0.0/24")...)
	clk.t = clk.t.Add(6 * time.Hour)
	m.Refresh(context.Background(), "cdn")
	h = hist()
	if len(h) != 2 || h[1].Event != "provider update" || h[1].PreviousVersion != first || !reflect.DeepEqual(h[1].Added, []string{"12.0.0.0/24"}) ||
		!reflect.DeepEqual(h[1].Removed, []string{"11.1.0.0/24"}) || h[1].CountBefore != 11 || h[1].CountAfter != 11 || h[1].Time != clk.t.Format(time.RFC3339) {
		t.Fatalf("%+v", h)
	}
	second := h[1].Version
	// a big change is held: one held entry (not one per refresh), the served version does not change
	f.set(ranges(30)[20:]...)
	for i := 0; i < 3; i++ {
		clk.t = clk.t.Add(6 * time.Hour)
		m.Refresh(context.Background(), "cdn")
	}
	h = hist()
	if len(h) != 3 || h[2].Event != "held" || h[2].Version != second || h[2].Reason == "" || h[2].RemovedCount != 10 || h[2].AddedCount != 10 {
		t.Fatalf("%+v", h)
	}
	// accept
	if _, err := RequestAccept(m.Dir, "cdn"); err != nil {
		t.Fatal(err)
	}
	m.applyAccepts()
	h = hist()
	if len(h) != 4 || h[3].Event != "accept" || h[3].PreviousVersion != second || h[3].CountAfter != 11 || h[3].Version == second {
		t.Fatalf("%+v", h)
	}
	if p, _ := m.Serve("cdn"); p.Version != h[3].Version {
		t.Fatal("version after accept")
	}
	// the last entries are in infra-hub status, and the command prints them as JSON
	st := m.Status()
	if got := st.Lists["cdn"].History; len(got) != 4 || got[3].Event != "accept" {
		t.Fatalf("%+v", got)
	}
	var out bytes.Buffer
	if err := HistoryReport(m.Dir, m.Lists, "cdn", 2, &out); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		List    string         `json:"list"`
		Entries []HistoryEntry `json:"entries"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil || doc.List != "cdn" || len(doc.Entries) != 2 || doc.Entries[1].Event != "accept" {
		t.Fatalf("%v %s", err, out.String())
	}
	if err := HistoryReport(m.Dir, m.Lists, "../x", 0, &out); err == nil {
		t.Fatal("a name that is not a configured list was accepted")
	}
}

func TestHistoryListsAreCappedButCountsAreExact(t *testing.T) {
	dir := t.TempDir()
	big := make([]string, 0, 1500)
	for i := 0; i < 1500; i++ {
		big = append(big, fmt.Sprintf("%d.%d.0.0/16", 11+i/256, i%256))
	}
	m := &IPManager{Dir: dir, Lists: map[string]IPList{"l": {Providers: []string{"p"}}}}
	m.save("p", ProviderState{CIDRs: big})
	m.recordChange("p", map[string][]string{"l": nil}, "first fetch", ProviderState{CIDRs: big})
	e := ReadHistory(dir, "l", 0)[0]
	if e.AddedCount != 1500 || len(e.Added) != historyListCap || !e.Truncated {
		t.Fatalf("%d %d %v", e.AddedCount, len(e.Added), e.Truncated)
	}
}

// The first word of a warning is its identity: kind:provider. Counts, error text and times may change without a new issue.
func TestWarningIdentityIsStableWhileTheDetailChanges(t *testing.T) {
	key := func(w string) string { k, _, _ := strings.Cut(w, " "); return k }
	f := newFakeProvider(t, ranges(10)...)
	m, clk := newIPTestManager(t, f)
	m.Refresh(context.Background(), "cdn")
	f.fail(500, "first error text")
	for i := 0; i < 3; i++ {
		clk.t = clk.t.Add(time.Hour)
		m.Refresh(context.Background(), "cdn")
	}
	p1, _ := m.Serve("cdn")
	f.fail(503, "a completely different error text")
	for i := 0; i < 2; i++ {
		clk.t = clk.t.Add(time.Hour)
		m.Refresh(context.Background(), "cdn")
	}
	p2, _ := m.Serve("cdn")
	if len(p1.Warnings) != 1 || len(p2.Warnings) != 1 || p1.Warnings[0] == p2.Warnings[0] || key(p1.Warnings[0]) != key(p2.Warnings[0]) || key(p1.Warnings[0]) != "failing:cdn" {
		t.Fatalf("%v / %v", p1.Warnings, p2.Warnings)
	}
	for _, w := range []string{"held:cdn", "stale:cdn", "state_error:cdn"} {
		if !regexp.MustCompile(`^[a-z_]+:[a-z0-9_-]+$`).MatchString(w) {
			t.Fatal(w)
		}
	}
}

func TestWarningsAreDedupedAndCappedForTheClient(t *testing.T) {
	dir := t.TempDir()
	m := &IPManager{Dir: dir, Lists: map[string]IPList{}, Now: func() time.Time { return time.Now() }}
	var providers []string
	for i := 0; i < 30; i++ {
		p := fmt.Sprintf("p%02d", i)
		providers = append(providers, p)
		os.WriteFile(m.path(p), []byte("{torn"), 0o600)
	}
	w := m.warnings(IPList{Providers: providers})
	if len(w) != MaxWarnings || !strings.Contains(strings.Join(w, "\n"), "more:all and 11 more") {
		t.Fatalf("%d %v", len(w), w)
	}
	if !sort.StringsAreSorted(w) {
		t.Fatal("not sorted")
	}
	// the same provider twice gives one warning
	if got := m.warnings(IPList{Providers: []string{"p00", "p00"}}); len(got) != 1 {
		t.Fatalf("%v", got)
	}
}

func TestAcceptNeedsNoPathLookupAfterTheDirectoryIsOpen(t *testing.T) {
	// On a real hub the state directory sits behind /var/lib/private (0700 root): once root has the directory open and
	// has become the hub user, the path is unreachable. Make it unreachable the same way and see that accept still works.
	f := newFakeProvider(t, ranges(10)...)
	m, clk := newIPTestManager(t, f)
	parent := filepath.Join(t.TempDir(), "private")
	os.MkdirAll(parent, 0o755)
	real := filepath.Join(parent, "iplists")
	os.Rename(m.Dir, real)
	m.Dir = real
	link := filepath.Join(t.TempDir(), "infra-hub-iplists") // like /var/lib/infra-hub -> private/infra-hub
	os.Symlink(real, link)
	m.Refresh(context.Background(), "cdn")
	f.set(ranges(30)[20:]...)
	clk.t = clk.t.Add(time.Hour)
	m.Refresh(context.Background(), "cdn")
	afterRootOpen = func() { os.Chmod(parent, 0) }
	defer func() { afterRootOpen = func() {}; os.Chmod(parent, 0o755) }()
	st, err := RequestAccept(link, "cdn")
	if err != nil || len(st.Pending) != 10 {
		t.Fatalf("%v", err)
	}
	os.Chmod(parent, 0o755)
	if b, err := os.ReadFile(filepath.Join(real, "accept", "cdn")); err != nil || strings.TrimSpace(string(b)) != ListVersion(ranges(30)[20:]) {
		t.Fatalf("%v %q", err, b)
	}
	if es, _ := os.ReadDir(filepath.Join(real, "accept")); len(es) != 1 {
		t.Fatalf("temp file left: %v", es)
	}
	m.applyAccepts()
	if m.state().Held {
		t.Fatal("not applied")
	}
}
