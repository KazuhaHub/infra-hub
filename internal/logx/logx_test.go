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
	token   = "cf-token-0123456789abcdef"
	nonce   = "nonce-9f8e7d6c5b4a"
	testKey = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF\n-----END PRIVATE KEY-----\n"
)

func logAll(l *slog.Logger) {
	AddSecret(token)
	AddSecret(nonce)
	l.Info("fetched with "+token, "nonce", nonce, "err", errors.New("rejected "+nonce), "key", testKey, "keyBytes", []byte(testKey))
	l.Warn("remote", "url", "https://user:"+token+"@example.org/repo.git", "tokenValue", Secret(token), "n", 3)
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
		for _, secret := range []string{token, nonce, "MC4CAQAwBQYDK2VwBCIE", "BEGIN PRIVATE KEY"} {
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
