package httpsapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func waitHub(t *testing.T, timeout time.Duration) (*testHub, *attest) {
	t.Helper()
	a := newAttest(t, goodFiles(1))
	h := withBundles(t, a)
	h.s.WaitTimeout = timeout
	return h, a
}

// startWait runs a wait request in the background; the result arrives on the channel.
func (h *testHub) startWait(ctx context.Context, host, etag, remote string) <-chan bundleResp {
	ch := make(chan bundleResp, 1)
	go func() {
		req := httptest.NewRequest("GET", "https://hub.example.org/v1/wait/"+host+"?etag="+etag, nil).WithContext(ctx)
		req.RemoteAddr = remote
		rec := &recorder{header: http.Header{}, code: 200}
		h.s.Handler().ServeHTTP(rec, req)
		ch <- bundleResp{rec.code, rec.header, rec.body.Bytes()}
	}()
	return ch
}

func (h *testHub) waitNow(t *testing.T, host, etag string) bundleResp {
	t.Helper()
	select {
	case r := <-h.startWait(context.Background(), host, etag, "192.0.2.1:1234"):
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("the wait request did not answer")
		return bundleResp{}
	}
}

func waitDoc(t *testing.T, r bundleResp) map[string]any {
	t.Helper()
	if r.code != 200 {
		t.Fatalf("status %d: %s", r.code, r.body)
	}
	var doc map[string]any
	if err := json.Unmarshal(r.body, &doc); err != nil || doc["apiVersion"] != "v1" {
		t.Fatalf("not a v1 document: %q", r.body)
	}
	return doc
}

func waitForCount(t *testing.T, h *testHub, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for h.s.waits.count() != n {
		if time.Now().After(deadline) {
			t.Fatalf("%d waiters, want %d", h.s.waits.count(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestWaitAnswersAtOnceWhenTheBundleDiffers(t *testing.T) {
	h, _ := waitHub(t, time.Minute)
	for _, etag := range []string{"", c40(9)} {
		doc := waitDoc(t, h.waitNow(t, "h1", etag))
		if doc["changed"] != true || doc["commit"] != c40(1) {
			t.Errorf("etag %q: %v", etag, doc)
		}
	}
}

func TestWaitHoldsUntilTheMirrorBringsANewBundle(t *testing.T) {
	h, a := waitHub(t, time.Minute)
	ch := h.startWait(context.Background(), "h1", c40(1), "192.0.2.1:1234")
	waitForCount(t, h, 1)
	select {
	case r := <-ch:
		t.Fatalf("answered before anything changed: %s", r.body)
	case <-time.After(100 * time.Millisecond):
	}
	// a poke with the same bundle changes nothing
	h.s.Bundles.Poke()
	select {
	case r := <-ch:
		t.Fatalf("answered for an unchanged bundle: %s", r.body)
	case <-time.After(100 * time.Millisecond):
	}
	a.commit(goodFiles(2))
	h.s.Bundles.Poke()
	select {
	case r := <-ch:
		doc := waitDoc(t, r)
		if doc["changed"] != true || doc["commit"] != c40(2) {
			t.Errorf("%v", doc)
		}
		if strings.Contains(string(r.body), "age1") || len(r.body) > 200 {
			t.Errorf("the answer carries more than the commit: %s", r.body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("not woken by the new bundle")
	}
	waitForCount(t, h, 0)
}

func TestWaitRechecksOnItsOwn(t *testing.T) {
	h, a := waitHub(t, time.Minute)
	h.s.WaitRecheck = 20 * time.Millisecond
	ch := h.startWait(context.Background(), "h1", c40(1), "192.0.2.1:1234")
	waitForCount(t, h, 1)
	a.commit(goodFiles(2)) // no Poke
	select {
	case r := <-ch:
		if waitDoc(t, r)["commit"] != c40(2) {
			t.Errorf("%s", r.body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a missed wake-up was never noticed")
	}
}

func TestWaitTimesOut(t *testing.T) {
	h, _ := waitHub(t, 150*time.Millisecond)
	start := time.Now()
	doc := waitDoc(t, h.waitNow(t, "h1", c40(1)))
	if doc["changed"] != false || doc["commit"] != nil {
		t.Errorf("%v", doc)
	}
	if time.Since(start) < 140*time.Millisecond {
		t.Error("answered before the timeout")
	}
	waitForCount(t, h, 0)
}

func TestWaitCapsPerHostAndTotal(t *testing.T) {
	h, _ := waitHub(t, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var held []<-chan bundleResp
	for i := 0; i < MaxWaitersPerHost; i++ {
		held = append(held, h.startWait(ctx, "h1", c40(1), fmt.Sprintf("192.0.2.%d:1", i+1)))
	}
	waitForCount(t, h, MaxWaitersPerHost)
	r := h.waitNow(t, "h1", c40(1))
	if r.code != 429 || errCodeOf(t, r) != "too_many_waiters" || r.header.Get("Retry-After") == "" {
		t.Fatalf("third waiter for one host: %d %s", r.code, r.body)
	}
	// another host is not affected
	other := h.startWait(ctx, "h2", c40(1), "192.0.2.50:1")
	waitForCount(t, h, MaxWaitersPerHost+1)
	cancel()
	for _, c := range append(held, other) {
		<-c
	}
	waitForCount(t, h, 0)

	// the total cap
	var w waiters
	for i := 0; i < MaxWaitersTotal; i++ {
		if !w.acquire(fmt.Sprintf("host%d", i)) {
			t.Fatalf("refused waiter %d", i)
		}
	}
	if w.acquire("one-more") {
		t.Error("the total cap did not hold")
	}
	w.release("host0")
	if !w.acquire("one-more") {
		t.Error("a released slot was not reusable")
	}
}

func TestWaitDisconnectFreesTheSlot(t *testing.T) {
	h, _ := waitHub(t, time.Minute)
	srv := httptest.NewServer(h.s.Handler())
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/v1/wait/h1?etag="+c40(1), nil)
	errc := make(chan error, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		errc <- err
	}()
	waitForCount(t, h, 1)
	cancel()
	<-errc
	waitForCount(t, h, 0)
}

func TestWaitLongerThanTheServerTimeouts(t *testing.T) {
	h, a := waitHub(t, 5*time.Second)
	srv := httptest.NewUnstartedServer(h.s.Handler())
	srv.Config.ReadTimeout = 200 * time.Millisecond
	srv.Config.WriteTimeout = 200 * time.Millisecond
	srv.Start()
	defer srv.Close()
	go func() {
		time.Sleep(700 * time.Millisecond)
		a.commit(goodFiles(2))
		h.s.Bundles.Poke()
	}()
	resp, err := http.Get(srv.URL + "/v1/wait/h1?etag=" + c40(1))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil || doc["changed"] != true {
		t.Fatalf("%v %v", doc, err)
	}
}

func TestWaitRefusals(t *testing.T) {
	h, _ := waitHub(t, time.Second)
	if r := h.waitNow(t, "nobody", c40(1)); r.code != 404 || errCodeOf(t, r) != "unknown_host" {
		t.Errorf("unknown host: %d %s", r.code, r.body)
	}
	if r := h.waitNow(t, "h1", "not-a-commit"); r.code != 400 {
		t.Errorf("bad etag: %d", r.code)
	}
	req := httptest.NewRequest("POST", "https://hub.example.org/v1/wait/h1?etag="+c40(1), nil)
	rec := &recorder{header: http.Header{}, code: 200}
	h.s.Handler().ServeHTTP(rec, req)
	if rec.code != 405 {
		t.Errorf("POST: %d", rec.code)
	}
	h.s.Bundles.Fresh = func() error { return fmt.Errorf("stale") }
	if r := h.waitNow(t, "h1", c40(1)); r.code != 503 || errCodeOf(t, r) != "stale_mirror" {
		t.Errorf("stale: %d", r.code)
	}
	h.s.Bundles = nil
	if r := h.waitNow(t, "h1", c40(1)); r.code != 503 {
		t.Errorf("no bundles: %d", r.code)
	}
}

func TestWaitRateLimitedPerPeer(t *testing.T) {
	h, _ := waitHub(t, time.Second)
	var last bundleResp
	for i := 0; i < 11; i++ {
		last = h.waitNow(t, "h1", "") // answers at once, still counts
	}
	if last.code != 429 || errCodeOf(t, last) != "rate_limited" {
		t.Fatalf("11th request: %d", last.code)
	}
	r := <-h.startWait(context.Background(), "h1", "", "192.0.2.77:1")
	if r.code != 200 {
		t.Errorf("another peer: %d", r.code)
	}
}
