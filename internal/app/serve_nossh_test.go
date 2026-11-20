package app

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/KazuhaHub/infra-hub/internal/config"
	"github.com/KazuhaHub/infra-hub/internal/hubkey"
	"github.com/KazuhaHub/infra-hub/internal/hubtrust"
	"github.com/KazuhaHub/infra-hub/internal/logx"
)

// A hub without `listen` runs no SSH server and still serves IP lists and certificates over HTTPS.
func TestServeWithoutSSH(t *testing.T) {
	dir := t.TempDir()
	key, err := hubkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	pin, _ := hubkey.Pin(key)
	keyPath := filepath.Join(dir, "hub.key")
	data, _ := hubkey.Marshal(key)
	if err := os.WriteFile(keyPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	id, _ := age.GenerateX25519Identity()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpsAddr := ln.Addr().String()
	ln.Close()
	cfgData, _ := json.Marshal(map[string]any{
		"repo": filepath.Join(dir, "infra.git"), "upstream": filepath.Join(dir, "no-such-upstream.git"),
		"clients":        map[string]any{"h1": map[string]string{"agePublicKey": id.Recipient().String()}},
		"httpsAddresses": []string{"127.0.0.1"}, "https": map[string]any{"listen": httpsAddr, "key": keyPath},
		"certs":   map[string]string{"a.example.org": "h1"},
		"ipLists": map[string]any{"edge": map[string]any{"manual": []string{"11.9.0.0/24"}}},
	})
	cfg, err := config.ParseConfig(cfgData)
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	logger, _ := logx.New(logs, "text", "debug")
	prev := slog.Default()
	logx.Install(logger)
	t.Cleanup(func() { slog.SetDefault(prev) })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { serve(ctx, cfg); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, logs, "https listening")
	if !strings.Contains(logs.String(), "ssh is off") {
		t.Errorf("no note that SSH is off:\n%s", logs.String())
	}

	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: hubtrust.Verifier{Pins: []string{pin}, Host: "127.0.0.1"}.TLSConfig()}}
	get := func(path string) (int, string) {
		resp, err := client.Get("https://" + httpsAddr + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := get("/v1/healthz"); code != 200 || !strings.Contains(body, `"version"`) {
		t.Errorf("healthz: %d %s", code, body)
	}
	if code, body := get("/v1/iplist/edge"); code != 200 || !strings.Contains(body, `"11.9.0.0/24"`) {
		t.Errorf("iplist: %d %s", code, body)
	}
	if code, body := get("/v1/iplist/other"); code != 404 {
		t.Errorf("unknown list: %d %s", code, body)
	}
	// The name is configured but nothing was issued: the hub is not serving it (no Cloudflare token here).
	if code, body := get("/v1/cert/h1/a.example.org"); code != 503 || !strings.Contains(body, "not_serving") {
		t.Errorf("cert: %d %s", code, body)
	}
	if code, _ := get("/v1/cert/h1/b.example.org"); code != 404 {
		t.Errorf("unknown cert: %d", code)
	}
}

// Without SSH, a hub whose HTTPS cannot start must fail, not idle.
func TestServeWithoutSSHFailsWhenHTTPSCannotStart(t *testing.T) {
	dir := t.TempDir()
	id, _ := age.GenerateX25519Identity()
	cfgData, _ := json.Marshal(map[string]any{
		"repo": filepath.Join(dir, "infra.git"), "upstream": filepath.Join(dir, "no-such-upstream.git"),
		"clients":        map[string]any{"h1": map[string]string{"agePublicKey": id.Recipient().String()}},
		"httpsAddresses": []string{"127.0.0.1"}, "https": map[string]any{"listen": "127.0.0.1:18443", "key": filepath.Join(dir, "missing.key")},
	})
	cfg, err := config.ParseConfig(cfgData)
	if err != nil {
		t.Fatal(err)
	}
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := serve(ctx, cfg); err == nil || ctx.Err() != nil {
		t.Fatalf("serve returned %v (context error %v)", err, ctx.Err())
	}
}
