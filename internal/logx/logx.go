// Package logx builds the program's slog logger (stderr, text or JSON) and keeps secrets out of it.
//
// The rule is that code never passes a secret to the logger. logx is the second line of defence: values registered
// with AddSecret, private key blocks and credentials inside URLs are replaced by [redacted] in every message and
// attribute before they are written, so a secret that arrives inside an error text still does not reach the journal.
package logx

import (
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"sync"
)

// Redacted replaces whatever may be a secret.
const Redacted = "[redacted]"

// Secret is a value that logs as [redacted] whatever it holds.
type Secret string

func (Secret) LogValue() slog.Value { return slog.StringValue(Redacted) }
func (Secret) String() string       { return Redacted }

var (
	mu      sync.RWMutex
	secrets []string
)

var (
	pemKey  = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|$)`)
	urlAuth = regexp.MustCompile(`(://)[^/@\s]+:[^/@\s]*@`)
)

// AddSecret registers a value (a token, a nonce, a password) that must never appear in the log. Very short values
// are ignored: replacing them would damage ordinary text.
func AddSecret(v string) {
	v = strings.TrimSpace(v)
	if len(v) < 6 {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	for _, s := range secrets {
		if s == v {
			return
		}
	}
	secrets = append(secrets, v)
}

// ResetSecrets forgets every registered value (for tests).
func ResetSecrets() {
	mu.Lock()
	defer mu.Unlock()
	secrets = nil
}

// Scrub returns s with registered secrets, private key blocks and URL credentials replaced.
func Scrub(s string) string {
	s = pemKey.ReplaceAllString(s, Redacted)
	s = urlAuth.ReplaceAllString(s, "${1}"+Redacted+"@")
	mu.RLock()
	defer mu.RUnlock()
	for _, sec := range secrets {
		s = strings.ReplaceAll(s, sec, Redacted)
	}
	return s
}

func replaceAttr(_ []string, a slog.Attr) slog.Attr {
	a.Value = a.Value.Resolve()
	switch a.Value.Kind() {
	case slog.KindString:
		a.Value = slog.StringValue(Scrub(a.Value.String()))
	case slog.KindAny:
		switch v := a.Value.Any().(type) {
		case error:
			a.Value = slog.StringValue(Scrub(v.Error()))
		case fmt.Stringer:
			a.Value = slog.StringValue(Scrub(v.String()))
		case []byte:
			a.Value = slog.StringValue(Scrub(string(v)))
		}
	}
	return a
}

// New returns a logger writing to w. format is "text" (key=value, the default) or "json"; level is debug, info, warn
// or error.
func New(w io.Writer, format, level string) (*slog.Logger, error) {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "", "info":
		lv = slog.LevelInfo
	case "warn", "warning":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		return nil, fmt.Errorf("log level %q: want debug, info, warn or error", level)
	}
	opts := &slog.HandlerOptions{Level: lv, ReplaceAttr: replaceAttr}
	switch strings.ToLower(format) {
	case "", "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	}
	return nil, fmt.Errorf("log format %q: want text or json", format)
}
