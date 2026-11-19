package logx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const (
	// unregistered is a credential that only the URL rule can catch: AddSecret never sees it.
	unregistered = "pw-never-registered-77aa"
	token        = "cf-token-0123456789abcdef"
	nonce        = "nonce-9f8e7d6c5b4a"
	testKey      = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF\n-----END PRIVATE KEY-----\n"
)

func logAll(l *slog.Logger) {
	AddSecret(token)
	AddSecret(nonce)
	l.Info("fetched with "+token, "nonce", nonce, "err", errors.New("rejected "+nonce), "key", testKey, "keyBytes", []byte(testKey))
	l.Warn("remote", "url", "https://user:"+unregistered+"@example.org/repo.git", "tokenValue", Secret(token), "n", 3)
	l.With("cert", "a.example.org").Error("failed", "err", fmt.Errorf("wrapped: %w", errors.New(token)), slog.Group("g", "inner", nonce))
}

func TestSecretsNeverReachTheOutput(t *testing.T) {
	t.Cleanup(ResetSecrets)
	for _, format := range []string{"text", "json"} {
		var buf bytes.Buffer
		l, err := New(&buf, format, "debug")
		if err != nil {
			t.Fatal(err)
		}
		logAll(l)
		out := buf.String()
		for _, secret := range []string{token, nonce, unregistered, "MC4CAQAwBQYDK2VwBCIE", "BEGIN PRIVATE KEY"} {
			if strings.Contains(out, secret) {
				t.Errorf("%s: output contains %q:\n%s", format, secret, out)
			}
		}
		if !strings.Contains(out, Redacted) || !strings.Contains(out, "a.example.org") {
			t.Errorf("%s: output lost its ordinary content:\n%s", format, out)
		}
	}
}

func TestFormatsAndLevels(t *testing.T) {
	var buf bytes.Buffer
	l, _ := New(&buf, "json", "warn")
	l.Info("hidden")
	l.Warn("shown", "host", "h1")
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil || rec["msg"] != "shown" || rec["host"] != "h1" || rec["level"] != "WARN" {
		t.Errorf("json record: %v %s", err, buf.String())
	}
	buf.Reset()
	l, _ = New(&buf, "", "")
	l.Info("bundle applied", "version", "1")
	if out := buf.String(); !strings.Contains(out, "msg=\"bundle applied\"") || !strings.Contains(out, "version=1") {
		t.Errorf("text record: %s", out)
	}
	l, _ = New(&buf, "text", "debug")
	buf.Reset()
	l.Debug("d")
	if buf.Len() == 0 {
		t.Error("debug level does not log debug")
	}
	if _, err := New(&buf, "xml", "info"); err == nil {
		t.Error("unknown format accepted")
	}
	if _, err := New(&buf, "text", "loud"); err == nil {
		t.Error("unknown level accepted")
	}
}

func TestShortValuesAreNotRegistered(t *testing.T) {
	t.Cleanup(ResetSecrets)
	AddSecret("ab")
	if got := Scrub("about the table"); got != "about the table" {
		t.Errorf("short value replaced: %q", got)
	}
}

func TestURLCredentialsAreRedactedWithoutRegistration(t *testing.T) {
	for in, leaked := range map[string]string{
		"fetch https://user:secretpw@example.org/x.git failed":      "secretpw",
		"fetch https://ghp_TOKEN123456@example.org/x.git failed":    "ghp_TOKEN123456",
		"fetch https://user:p@ss:w@rd@example.org/x.git failed":     "p@ss",
		"fetch ssh://git@example.org:22/x.git failed":               "git@",
		"fetch https://user:secretpw@example.org:8443/x?a=b failed": "secretpw",
	} {
		got := Scrub(in)
		if strings.Contains(got, leaked) || !strings.Contains(got, "example.org") || !strings.Contains(got, Redacted+"@") {
			t.Errorf("Scrub(%q) = %q", in, got)
		}
	}
	for _, plain := range []string{"https://example.org/x.git", "mail me at a@b.org", "git@example.org:x/y.git"} {
		if got := Scrub(plain); got != plain {
			t.Errorf("Scrub(%q) changed it to %q", plain, got)
		}
	}
}

type panicky struct{ p *int }

func (x *panicky) String() string { return fmt.Sprint(*x.p) }

type holder struct {
	Name string
	Auth string
}

func TestOtherValuesAreScrubbed(t *testing.T) {
	t.Cleanup(ResetSecrets)
	AddSecret(token)
	for _, format := range []string{"text", "json"} {
		var buf bytes.Buffer
		l, _ := New(&buf, format, "info")
		var nilPanicky *panicky
		l.Info("values", "struct", holder{"a", token}, "ptr", &holder{"b", token}, "list", []string{"x", token}, "map", map[string]string{"k": token},
			"panics", nilPanicky, "plain", holder{"c", "d"}, "n", 42)
		out := buf.String()
		if strings.Contains(out, token) {
			t.Errorf("%s: a structured value leaked the secret:\n%s", format, out)
		}
		if !strings.Contains(out, "panics") || !strings.Contains(out, "plain") {
			t.Errorf("%s: a record was lost:\n%s", format, out)
		}
	}
	// a structured value without a secret keeps its JSON form
	var buf bytes.Buffer
	l, _ := New(&buf, "json", "info")
	l.Info("v", "plain", holder{"c", "d"})
	if !strings.Contains(buf.String(), `"plain":{"Name":"c","Auth":"d"}`) {
		t.Errorf("structured value flattened: %s", buf.String())
	}
}

func TestNoTimeKeyUnderJournal(t *testing.T) {
	var buf bytes.Buffer
	t.Setenv("JOURNAL_STREAM", "8:12345")
	l, _ := New(&buf, "text", "info")
	l.Info("hello", "host", "h1")
	if out := buf.String(); strings.Contains(out, "time=") || !strings.Contains(out, "msg=hello") {
		t.Errorf("journal text output: %s", out)
	}
	buf.Reset()
	l, _ = New(&buf, "json", "info") // machines reading JSON keep the time
	l.Info("hello")
	if !strings.Contains(buf.String(), `"time"`) {
		t.Errorf("json lost the time: %s", buf.String())
	}
	buf.Reset()
	t.Setenv("JOURNAL_STREAM", "")
	l, _ = New(&buf, "text", "info")
	l.Info("hello")
	if !strings.Contains(buf.String(), "time=") {
		t.Errorf("text lost the time outside the journal: %s", buf.String())
	}
}

func TestRecentNonceIsRedactedAndRingIsBounded(t *testing.T) {
	t.Cleanup(ResetSecrets)
	const n = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
	AddRecent(n)
	var buf bytes.Buffer
	l, _ := New(&buf, "text", "info")
	l.Info("report "+n, "nonce", n, "err", errors.New("bad "+n))
	if out := buf.String(); strings.Contains(out, n) || !strings.Contains(out, Redacted) {
		t.Fatalf("nonce reached the log: %s", out)
	}
	for i := 0; i < recentMax; i++ { // pushes the first value out of the ring
		AddRecent(fmt.Sprintf("filler-%04d", i))
	}
	mu.RLock()
	defer mu.RUnlock()
	for _, v := range recent {
		if v == n {
			t.Fatal("ring did not forget the oldest value")
		}
	}
}
