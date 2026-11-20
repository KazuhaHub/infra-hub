package httpsapi

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/logx"
	"github.com/KazuhaHub/infra-hub/internal/state"
)

func TestHealthz(t *testing.T) {
	h := newHub(t)
	code, doc := h.do(t, "GET", "/v1/healthz", "")
	if code != 200 || doc["apiVersion"] != "v1" || doc["status"] != "ok" || len(doc) != 2 {
		t.Fatalf("%d %v", code, doc)
	}
	if code, doc := h.do(t, "POST", "/v1/healthz", ""); code != 405 || errCode(doc) != "method_not_allowed" {
		t.Errorf("POST healthz: %d %v", code, doc)
	}
	if code, doc := h.do(t, "GET", "/v1/nothing", ""); code != 404 || errCode(doc) != "not_found" || doc["apiVersion"] != "v1" {
		t.Errorf("unknown path: %d %v", code, doc)
	}
}

func errCode(doc map[string]any) string {
	e, _ := doc["error"].(map[string]any)
	c, _ := e["code"].(string)
	return c
}

func TestChallengeAndReportHappyPath(t *testing.T) {
	h := newHub(t)
	code, doc := h.do(t, "POST", "/v1/challenge", `{"host":"h1"}`)
	if code != 200 || doc["apiVersion"] != "v1" {
		t.Fatalf("%d %v", code, doc)
	}
	if doc["expiresAt"] != t0.Add(5*time.Minute).Format(time.RFC3339) {
		t.Errorf("expiresAt %v", doc["expiresAt"])
	}
	armored := doc["challenge"].(string)
	if !strings.HasPrefix(armored, "-----BEGIN AGE ENCRYPTED FILE-----") {
		t.Errorf("challenge is not armored age: %.40q", armored)
	}
	nonce := decryptChallenge(t, h.ids["h1"], armored)
	// h2's key cannot read h1's challenge.
	if _, err := decryptWith(h.ids["h2"], armored); err == nil {
		t.Error("another host's key decrypted the challenge")
	}
	h.now = h.now.Add(time.Minute)
	code, doc = h.do(t, "POST", "/v1/report", reportBodyFor("h1", nonce, goodReport))
	if code != 200 || doc["status"] != "ok" || doc["apiVersion"] != "v1" {
		t.Fatalf("report: %d %v", code, doc)
	}
	rep := h.store.st.Reports()["h1"]
	if rep.AppliedCommit != commit || rep.Result != "ok" || rep.Message != "applied" || rep.Time != "2026-11-19T08:00:00Z" ||
		rep.ReceivedAt != t0.Add(time.Minute).Format(time.RFC3339) || len(rep.Features) != 2 {
		t.Errorf("stored %+v", rep)
	}
	reloaded, err := state.LoadState(h.state) // it reached the file
	if err != nil || reloaded.Reports()["h1"].AppliedCommit != commit {
		t.Errorf("not persisted: %v", err)
	}
	// The same nonce again is refused.
	code, doc = h.do(t, "POST", "/v1/report", reportBodyFor("h1", nonce, goodReport))
	if code != 401 || errCode(doc) != "bad_nonce" {
		t.Errorf("reused nonce: %d %v", code, doc)
	}
}

func TestNonceRefusals(t *testing.T) {
	h := newHub(t)
	n1 := h.challenge(t, "h1")
	// A nonce issued to h1 does not work for h2, and the refusal does not burn it.
	if code, doc := h.do(t, "POST", "/v1/report", reportBodyFor("h2", n1, goodReport)); code != 401 || errCode(doc) != "bad_nonce" {
		t.Errorf("other host: %d %v", code, doc)
	}
	// Expired.
	h.now = h.now.Add(5*time.Minute + time.Second)
	if code, doc := h.do(t, "POST", "/v1/report", reportBodyFor("h1", n1, goodReport)); code != 401 || errCode(doc) != "bad_nonce" {
		t.Errorf("expired: %d %v", code, doc)
	}
	// Never issued, malformed, empty, unknown host.
	for name, body := range map[string]string{
		"random":       reportBodyFor("h1", strings.Repeat("ab", 32), goodReport),
		"short":        reportBodyFor("h1", "abcd", goodReport),
		"not hex":      reportBodyFor("h1", strings.Repeat("zz", 32), goodReport),
		"empty":        reportBodyFor("h1", "", goodReport),
		"unknown host": reportBodyFor("nobody", strings.Repeat("ab", 32), goodReport),
	} {
		if code, doc := h.do(t, "POST", "/v1/report", body); code != 401 || errCode(doc) != "bad_nonce" {
			t.Errorf("%s: %d %v", name, code, doc)
		}
	}
	// The right host can still use a nonce that another host tried.
	n2 := h.challenge(t, "h1")
	h.do(t, "POST", "/v1/report", reportBodyFor("h2", n2, goodReport))
	if code, _ := h.do(t, "POST", "/v1/report", reportBodyFor("h1", n2, goodReport)); code != 200 {
		t.Errorf("the owner of the nonce was locked out: %d", code)
	}
	if h.s.nonces.size() != 0 {
		t.Errorf("%d nonces left", h.s.nonces.size())
	}
}

func TestChallengeRefusals(t *testing.T) {
	h := newHub(t)
	if code, doc := h.do(t, "POST", "/v1/challenge", `{"host":"nobody"}`); code != 404 || errCode(doc) != "unknown_host" {
		t.Errorf("unknown host: %d %v", code, doc)
	}
	for name, body := range map[string]string{"empty": ``, "no host": `{}`, "extra field": `{"host":"h1","x":1}`, "not json": `host=h1`, "two": `{"host":"h1"}{"host":"h2"}`} {
		if code, doc := h.do(t, "POST", "/v1/challenge", body); code != 400 || errCode(doc) != "bad_request" {
			t.Errorf("%s: %d %v", name, code, doc)
		}
	}
	big := `{"host":"h1","pad":"` + strings.Repeat("x", 2000) + `"}`
	if code, doc := h.do(t, "POST", "/v1/challenge", big); code != 413 || errCode(doc) != "too_large" {
		t.Errorf("oversize challenge request: %d %v", code, doc)
	}
	if code, doc := h.do(t, "GET", "/v1/challenge", ""); code != 405 {
		t.Errorf("GET challenge: %d %v", code, doc)
	}
}

func TestReportRefusals(t *testing.T) {
	h := newHub(t)
	pad := strings.Repeat("x", MaxBody)
	nonce := h.challenge(t, "h1")
	// An oversize body is refused as such, before anything else, and does not consume the nonce.
	if code, doc := h.do(t, "POST", "/v1/report", reportBodyFor("h1", nonce, `{"message":"`+pad+`"}`)); code != 413 || errCode(doc) != "too_large" {
		t.Fatalf("oversize: %d %v", code, doc)
	}
	bad := map[string]string{
		"not json":         `report`,
		"no report":        `{"apiVersion":"v1","host":"h1","nonce":"` + nonce + `"}`,
		"wrong apiVersion": `{"apiVersion":"v2","host":"h1","nonce":"` + nonce + `","report":` + goodReport + `}`,
		"unknown envelope": `{"apiVersion":"v1","host":"h1","nonce":"` + nonce + `","report":` + goodReport + `,"x":1}`,
	}
	for name, body := range bad {
		if code, doc := h.do(t, "POST", "/v1/report", body); code != 400 || errCode(doc) != "bad_report" {
			t.Errorf("%s: %d %v", name, code, doc)
		}
	}
	// A report that fails the schema is refused with 400 (the nonce is spent: ask for a new challenge).
	rep := func(s string) string { return strings.NewReplacer("COMMIT", commit).Replace(s) }
	for name, r := range map[string]string{
		"unknown field":   rep(`{"appliedCommit":"COMMIT","result":"ok","time":"2026-11-19T08:00:00Z","extra":1}`),
		"short commit":    `{"appliedCommit":"abc123","result":"ok","time":"2026-11-19T08:00:00Z"}`,
		"upper commit":    rep(`{"appliedCommit":"` + strings.ToUpper(commit) + `","result":"ok","time":"2026-11-19T08:00:00Z"}`),
		"bad result":      rep(`{"appliedCommit":"COMMIT","result":"great","time":"2026-11-19T08:00:00Z"}`),
		"no time":         rep(`{"appliedCommit":"COMMIT","result":"ok"}`),
		"bad time":        rep(`{"appliedCommit":"COMMIT","result":"ok","time":"yesterday"}`),
		"long message":    rep(`{"appliedCommit":"COMMIT","result":"ok","time":"2026-11-19T08:00:00Z","message":"` + strings.Repeat("m", 5000) + `"}`),
		"bad feature":     rep(`{"appliedCommit":"COMMIT","result":"ok","time":"2026-11-19T08:00:00Z","features":[{"name":"../x","result":"ok"}]}`),
		"feature result":  rep(`{"appliedCommit":"COMMIT","result":"ok","time":"2026-11-19T08:00:00Z","features":[{"name":"a","result":"meh"}]}`),
		"duplicate feat.": rep(`{"appliedCommit":"COMMIT","result":"ok","time":"2026-11-19T08:00:00Z","features":[{"name":"a","result":"ok"},{"name":"a","result":"ok"}]}`),
		"not an object":   `[1]`,
	} {
		h.now = h.now.Add(5 * time.Second) // stay under the rate limits
		n := h.challenge(t, "h2")
		if code, doc := h.do(t, "POST", "/v1/report", reportBodyFor("h2", n, r)); code != 400 || errCode(doc) != "bad_report" {
			t.Errorf("%s: %d %v", name, code, doc)
		}
	}
	if len(h.store.st.Reports()) != 0 {
		t.Error("a refused report was stored")
	}
	// The nonce survived all the envelope refusals and the oversize one.
	if code, _ := h.do(t, "POST", "/v1/report", reportBodyFor("h1", nonce, goodReport)); code != 200 {
		t.Errorf("the nonce was burnt by a malformed envelope: %d", code)
	}
}

func TestRateLimits(t *testing.T) {
	// Per peer address.
	h := newHub(t)
	var got429 bool
	for i := 0; i < 40; i++ {
		if code, doc := h.do(t, "POST", "/v1/challenge", `{"host":"h1"}`); code == 429 {
			got429 = errCode(doc) == "rate_limited"
			break
		}
	}
	if !got429 {
		t.Error("no per-address limit")
	}
	if code, _ := h.doFromBody(t, "198.51.100.9:1", `{"host":"h2"}`); code != 200 {
		t.Errorf("another address was limited too: %d", code)
	}
	h.now = h.now.Add(time.Minute) // buckets refill
	if code, _ := h.do(t, "POST", "/v1/challenge", `{"host":"h1"}`); code != 200 {
		t.Errorf("limit did not recover: %d", code)
	}

	// Per host, from many addresses.
	h = newHub(t)
	ok, limited := 0, 0
	for i := 0; i < 30; i++ {
		code, _ := h.doFromBody(t, fmt.Sprintf("203.0.113.%d:1", i+1), `{"host":"h1"}`)
		switch code {
		case 200:
			ok++
		case 429:
			limited++
		}
	}
	if ok != 20 || limited != 10 {
		t.Errorf("per-host limit: %d ok, %d limited", ok, limited)
	}
	if code, _ := h.doFromBody(t, "203.0.113.200:1", `{"host":"h2"}`); code != 200 {
		t.Errorf("limiting h1 limited h2: %d", code)
	}
	// Reports are limited per address too.
	h = newHub(t)
	limited = 0
	for i := 0; i < 40; i++ {
		if code, _ := h.do(t, "POST", "/v1/report", reportBodyFor("h1", strings.Repeat("ab", 32), goodReport)); code == 429 {
			limited++
		}
	}
	if limited == 0 {
		t.Error("report is not rate limited")
	}
}

func (h *testHub) doFromBody(t *testing.T, remote, body string) (int, map[string]any) {
	t.Helper()
	return h.doFrom(t, remote, "POST", "/v1/challenge", strings.NewReader(body))
}

func TestIPv6SharesALimitPerSlash64(t *testing.T) {
	if remoteKey("[2001:db8:1:2:aaaa::1]:5") != remoteKey("[2001:db8:1:2:bbbb::2]:6") {
		t.Error("same /64 got different keys")
	}
	if remoteKey("[2001:db8:1:2::1]:5") == remoteKey("[2001:db8:1:3::1]:5") {
		t.Error("different /64 shared a key")
	}
	if remoteKey("[::ffff:192.0.2.1]:5") != "192.0.2.1" {
		t.Error("mapped address")
	}
}

func TestNonceStoreIsBounded(t *testing.T) {
	s := newNonceStore()
	now := t0
	for i := 0; i < maxNonces+300; i++ {
		var n [32]byte
		n[0], n[1], n[2] = byte(i), byte(i>>8), byte(i>>16)
		host := fmt.Sprintf("h%d", i/maxNoncesPerHost) // many hosts: only the global bound can stop this
		_, _ = s.issue(host, n, now)
	}
	if s.size() > maxNonces {
		t.Fatalf("store grew to %d", s.size())
	}
	// Expired entries make room again.
	now = now.Add(ChallengeTTL + time.Second)
	var n [32]byte
	n[5] = 1
	if _, err := s.issue("fresh", n, now); err != nil {
		t.Errorf("no room after expiry: %v", err)
	}
	// One host keeps only its newest nonces.
	s = newNonceStore()
	var first [32]byte
	for i := 0; i < maxNoncesPerHost+3; i++ {
		var n [32]byte
		n[0] = byte(i + 1)
		if i == 0 {
			first = n
		}
		if _, err := s.issue("h", n, now); err != nil {
			t.Fatal(err)
		}
	}
	if s.size() != maxNoncesPerHost || s.consume("h", first, now) {
		t.Errorf("per-host bound: %d entries, oldest usable", s.size())
	}
}

func TestNonceNeverLogged(t *testing.T) {
	t.Cleanup(logx.ResetSecrets)
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	var buf bytes.Buffer
	logger, _ := logx.New(&buf, "text", "debug")
	slog.SetDefault(logger)
	h := newHub(t)
	nonce := h.challenge(t, "h1")
	longMessage := `{"appliedCommit":"` + commit + `","result":"failed","message":"secret-looking-text-xyz","time":"2026-11-19T08:00:00Z"}`
	if code, _ := h.do(t, "POST", "/v1/report", reportBodyFor("h1", nonce, longMessage)); code != 200 {
		t.Fatal(code)
	}
	// Even if some other code path logged the nonce, logx scrubs it.
	slog.Info("oops", "nonce", nonce, "err", fmt.Errorf("bad %s", nonce))
	out := buf.String()
	if strings.Contains(out, nonce) {
		t.Errorf("the nonce is in the log:\n%s", out)
	}
	if strings.Contains(out, "secret-looking-text-xyz") {
		t.Errorf("the report message is in the log:\n%s", out)
	}
	if !strings.Contains(out, "report received") || !strings.Contains(out, "host=h1") || !strings.Contains(out, "result=failed") || !strings.Contains(out, "appliedCommit="+commit) {
		t.Errorf("the report line is missing:\n%s", out)
	}
}

func TestStrayBracketAfterJSONIsRefused(t *testing.T) {
	h := newHub(t)
	if code, _ := h.do(t, "POST", "/v1/challenge", `{"host":"h1"}}`); code != 400 {
		t.Errorf("stray bracket: %d", code)
	}
}

// The agent's cycle results are all accepted, with or without an applied commit; any other word is refused.
func TestReportAcceptsAgentResults(t *testing.T) {
	h := newHub(t)
	for _, result := range []string{"ok", "failed", "verified", "rejected", "unreachable", "unchanged"} {
		for _, applied := range []string{commit, ""} {
			h.now = h.now.Add(time.Minute) // keep clear of the rate limits
			nonce := h.challenge(t, "h1")
			body := reportBodyFor("h1", nonce, `{"appliedCommit":"`+applied+`","result":"`+result+`","message":"m","time":"2026-11-19T08:00:00Z"}`)
			if code, doc := h.do(t, "POST", "/v1/report", body); code != 200 {
				t.Errorf("result %s, applied %q: %d %v", result, applied, code, doc)
			}
			if got := h.store.st.Reports()["h1"]; got.Result != result || got.AppliedCommit != applied {
				t.Errorf("stored %+v", got)
			}
		}
	}
	nonce := h.challenge(t, "h1")
	for _, result := range []string{"", "OK", "applied", "skipped"} {
		body := reportBodyFor("h1", nonce, `{"appliedCommit":"`+commit+`","result":"`+result+`","time":"2026-11-19T08:00:00Z"}`)
		if code, doc := h.do(t, "POST", "/v1/report", body); code != 400 {
			t.Errorf("result %q: %d %v", result, code, doc)
		}
		h.now = h.now.Add(time.Minute)
		nonce = h.challenge(t, "h1")
	}
}

func TestReportRejectedHubs(t *testing.T) {
	h := newHub(t)
	send := func(hubs string) (int, map[string]any) {
		h.now = h.now.Add(time.Minute)
		nonce := h.challenge(t, "h1")
		return h.do(t, "POST", "/v1/report", reportBodyFor("h1", nonce, `{"appliedCommit":"`+commit+`","result":"verified","time":"2026-11-19T08:00:00Z","rejectedHubs":`+hubs+`}`))
	}
	if code, doc := send(`["https://hub1.example.org:8443","https://192.0.2.10"]`); code != 200 {
		t.Fatalf("%d %v", code, doc)
	}
	if got := h.store.st.Reports()["h1"].RejectedHubs; len(got) != 2 || got[0] != "https://hub1.example.org:8443" {
		t.Errorf("stored %v", got)
	}
	nine := `["https://a.example.org","https://b.example.org","https://c.example.org","https://d.example.org","https://e.example.org","https://f.example.org","https://g.example.org","https://h.example.org","https://i.example.org"]`
	for name, v := range map[string]string{"nine": nine, "not a url": `["hub"]`, "path": `["https://a.example.org/x"]`, "http": `["http://a.example.org"]`, "not a list": `"https://a.example.org"`} {
		if code, _ := send(v); code != 400 {
			t.Errorf("%s: %d", name, code)
		}
	}
	eight := strings.Replace(nine, `,"https://i.example.org"`, "", 1)
	if code, doc := send(eight); code != 200 {
		t.Errorf("eight: %d %v", code, doc)
	}
}
