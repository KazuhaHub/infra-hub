package app

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"net"

	"github.com/KazuhaHub/infra-hub/internal/config"
	"github.com/KazuhaHub/infra-hub/internal/hubtrust"
	"github.com/KazuhaHub/infra-hub/internal/logx"
)

// The hub is its HTTPS server. The config here is one written for v0.9.0 (SSH keys and all): the SSH keys are
// ignored, nothing listens on the old SSH address, and certificates and IP lists are served over HTTPS.
func TestServeStartsWithHTTPSOnly(t *testing.T) {
	dir := t.TempDir()
	keyPath, pin := writeHubKey(t, dir)
	id, _ := age.GenerateX25519Identity()
	sshAddr, httpsAddr := freeAddr(t), freeAddr(t)
	const sshKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dB4w4rTZe"
	cfgData, _ := json.Marshal(map[string]any{
		"listen": sshAddr, "hostKey": filepath.Join(dir, "host_key"),
		"repo": filepath.Join(dir, "infra.git"), "upstream": filepath.Join(dir, "no-such-upstream.git"),
		"clients":        map[string]any{"h1": map[string]string{"sshKey": sshKey, "agePublicKey": id.Recipient().String()}, "h2": sshKey},
		"httpsAddresses": []string{"127.0.0.1"}, "https": map[string]any{"listen": httpsAddr, "key": keyPath},
		"certs":   map[string]string{"a.example.org": "h1"},
		"ipLists": map[string]any{"edge": map[string]any{"manual": []string{"11.9.0.0/24"}, "hosts": []string{"h1"}}},
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
	if conn, err := net.DialTimeout("tcp", sshAddr, time.Second); err == nil {
		conn.Close()
		t.Error("something listens on the old SSH address")
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
	if code, _ := get("/v1/iplist/other"); code != 404 {
		t.Errorf("unknown list: %d", code)
	}
	// The name is configured but nothing was issued: the hub is not serving it (no Cloudflare token here).
	if code, body := get("/v1/cert/h1/a.example.org"); code != 503 || !strings.Contains(body, "not_serving") {
		t.Errorf("cert: %d %s", code, body)
	}
	if code, _ := get("/v1/cert/h1/b.example.org"); code != 404 {
		t.Errorf("unknown cert: %d", code)
	}
}

// serve without an HTTPS listener has nothing to serve and says so.
func TestServeWithoutHTTPSListenerFails(t *testing.T) {
	cfg := config.Config{Repo: filepath.Join(t.TempDir(), "infra.git"), Upstream: "x", MirrorIntervalSeconds: 60}
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	if err := serve(context.Background(), cfg); err == nil {
		t.Fatal("serve returned nil")
	}
}
