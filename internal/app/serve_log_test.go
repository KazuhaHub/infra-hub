package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	legolog "github.com/go-acme/lego/v4/log"

	"github.com/KazuhaHub/infra-hub/internal/certs"
	"github.com/KazuhaHub/infra-hub/internal/config"
	"github.com/KazuhaHub/infra-hub/internal/hubkey"
	"github.com/KazuhaHub/infra-hub/internal/hubtrust"
	"github.com/KazuhaHub/infra-hub/internal/logx"
	"github.com/KazuhaHub/infra-hub/internal/testutil"
)

// syncBuffer is a log destination that the hub's goroutines and the test can use together.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// makeBundle makes a bundle for name (a leaf under a throwaway CA) that is valid for 60 days; it also returns the
// base64 body of the leaf's private key.
func makeBundle(t *testing.T, name string) (certs.Bundle, string) {
	return makeBundleUntil(t, name, time.Now().Add(60*24*time.Hour))
}

// makeBundleUntil is makeBundle with a chosen expiry of the leaf.
func makeBundleUntil(t *testing.T, name string, notAfter time.Time) (certs.Bundle, string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	return certs.Bundle{Fullchain: chain, Privkey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})}, base64.StdEncoding.EncodeToString(keyDER)
}

// The hub runs with a Cloudflare token, a stored certificate key, a client that fetches the certificate and one that
// is turned away: none of the secrets may show up in the log, at debug level, in text or JSON.
func TestServeLogHasNoSecrets(t *testing.T) {
	testutil.NeedTool(t, "git")
	const cfToken = "cf-API-token-do-not-log-0123456789"
	for _, tc := range []struct{ format, issuer string }{{"text", "lego"}, {"json", "lego"}, {"text", "failing"}, {"json", "failing"}} {
		format := tc.format
		t.Run(tc.format+"-"+tc.issuer, func(t *testing.T) {
			t.Cleanup(logx.ResetSecrets)
			if tc.issuer == "failing" {
				// An issuer whose error text, and whose own log line, carry the token that serve registered.
				prevIssuer := newIssuer
				newIssuer = func(_ config.Config, token string) certs.Issuer { return failingIssuer{token} }
				t.Cleanup(func() { newIssuer = prevIssuer })
			}
			dir := t.TempDir()
			addr := freeAddr(t)
			keyPath, pin := writeHubKey(t, dir)
			id, _ := age.GenerateX25519Identity()
			tokenFile := filepath.Join(dir, "cf_token")
			os.WriteFile(tokenFile, []byte(cfToken+"\n"), 0o600)
			cfgData, _ := json.Marshal(map[string]any{
				"repo": filepath.Join(dir, "infra.git"), "upstream": filepath.Join(dir, "no-such-upstream.git"),
				"httpsAddresses": []string{"127.0.0.1"}, "https": map[string]any{"listen": addr, "key": keyPath},
				"clients": map[string]any{"h1": map[string]string{"agePublicKey": id.Recipient().String()}},
				"certs":   map[string]string{"stored.example.org": "h1", "new.example.org": "h1"}, "cloudflareTokenFile": tokenFile,
				"acmeDirectory": "https://127.0.0.1:1/directory",
			})
			cfg, err := config.ParseConfig(cfgData)
			if err != nil {
				t.Fatal(err)
			}
			bundle, keyBody := makeBundle(t, "stored.example.org")
			if err := (certs.CertStore{Dir: cfg.CertDir}).SaveBundle("stored.example.org", bundle); err != nil {
				t.Fatal(err)
			}

			logs := &syncBuffer{}
			logger, err := logx.New(logs, format, "debug")
			if err != nil {
				t.Fatal(err)
			}
			prev, prevLego := slog.Default(), legolog.Logger
			logx.Install(logger)
			t.Cleanup(func() { slog.SetDefault(prev); legolog.Logger = prevLego })

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { serve(ctx, cfg); close(done) }()
			t.Cleanup(func() { cancel(); <-done })

			waitFor(t, logs, "https listening")
			// the owner's certificate is fetched (age-encrypted, so the key is not readable in the body); an unknown name is turned away
			client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: hubtrust.Verifier{Pins: []string{pin}, Host: "127.0.0.1"}.TLSConfig()}}
			for path, want := range map[string]int{"/v1/cert/h1/stored.example.org": 200, "/v1/cert/h1/unknown.example.org": 404} {
				resp, err := client.Get("https://" + addr + path)
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode != want || (want == 200 && strings.Contains(string(body), "PRIVATE KEY")) {
					t.Errorf("%s: %d", path, resp.StatusCode)
				}
			}
			waitFor(t, logs, "cert served")
			waitFor(t, logs, "certificate attempt failed") // new.example.org: the CA is unreachable
			cancel()
			<-done
			out := logs.String()
			for what, secret := range map[string]string{"Cloudflare token": cfToken, "certificate key": keyBody, "key header": "PRIVATE KEY"} {
				if secret != "" && strings.Contains(out, secret) {
					t.Errorf("the log contains the %s:\n%s", what, out)
				}
			}
			if tc.issuer == "failing" && (!strings.Contains(out, logx.Redacted) || !strings.Contains(out, "CF API rejected")) {
				t.Errorf("the failing issuer's error was not logged, redacted:\n%s", out)
			}
			if !strings.Contains(out, "stored.example.org") {
				t.Errorf("the log lost its content:\n%s", out)
			}
		})
	}
}

// failingIssuer fails the way a broken API call can: with the credential inside the error text and in lego's log.
type failingIssuer struct{ token string }

func (f failingIssuer) Obtain(_ context.Context, name string) (certs.Bundle, error) {
	legolog.Infof("[%s] dns-01 with token %s", name, f.token)
	return certs.Bundle{}, fmt.Errorf("CF API rejected token %s for %s", f.token, name)
}

func waitFor(t *testing.T, b *syncBuffer, text string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !strings.Contains(b.String(), text) {
		if time.Now().After(deadline) {
			t.Fatalf("no %q in the log:\n%s", text, b.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// freeAddr is a loopback address that nothing listens on now.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// writeHubKey writes a hub identity key into dir and returns its path and pin.
func writeHubKey(t *testing.T, dir string) (path, pin string) {
	t.Helper()
	key, err := hubkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if pin, err = hubkey.Pin(key); err != nil {
		t.Fatal(err)
	}
	data, _ := hubkey.Marshal(key)
	path = filepath.Join(dir, "hub.key")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, pin
}

// A hub identity key that is missing, readable by others or not a key makes the hub fail at start: HTTPS is its only
// listener, so it must not idle.
func TestServeWithAnUnusableHTTPSKeyFails(t *testing.T) {
	good, err := hubkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	for name, setup := range map[string]func(path string){
		"missing":   func(string) {},
		"mode 0644": func(p string) { data, _ := hubkey.Marshal(good); os.WriteFile(p, data, 0o644) },
		"not a key": func(p string) { os.WriteFile(p, []byte("nope"), 0o600) },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			httpsAddr := freeAddr(t)
			keyPath := filepath.Join(dir, "hub.key")
			setup(keyPath)
			cfgData, _ := json.Marshal(map[string]any{
				"repo": filepath.Join(dir, "infra.git"), "upstream": filepath.Join(dir, "no-such-upstream.git"),
				"httpsAddresses": []string{"127.0.0.1"}, "https": map[string]any{"listen": httpsAddr, "key": keyPath},
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
			if conn, err := net.DialTimeout("tcp", httpsAddr, time.Second); err == nil {
				conn.Close()
				t.Error("something listens on the HTTPS address")
			}
		})
	}
}
