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
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	legolog "github.com/go-acme/lego/v4/log"
	"golang.org/x/crypto/ssh"

	"github.com/KazuhaHub/infra-hub/internal/certs"
	"github.com/KazuhaHub/infra-hub/internal/config"
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
			signer, clientKey := testutil.NewKey(t)
			stranger, _ := testutil.NewKey(t)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := ln.Addr().String()
			ln.Close()
			tokenFile := filepath.Join(dir, "cf_token")
			os.WriteFile(tokenFile, []byte(cfToken+"\n"), 0o600)
			cfgData, _ := json.Marshal(map[string]any{
				"listen": addr, "repo": filepath.Join(dir, "infra.git"), "upstream": filepath.Join(dir, "no-such-upstream.git"),
				"hostKey": filepath.Join(dir, "host_key"), "clients": map[string]string{"h1": clientKey},
				"certs": map[string]string{"stored.example.org": "h1", "new.example.org": "h1"}, "cloudflareTokenFile": tokenFile,
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

			waitFor(t, logs, "listening")
			hostKey, _ := os.ReadFile(cfg.HostKey)
			// one client fetches the stored certificate, one is turned away
			for _, s := range []ssh.Signer{signer, stranger} {
				c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "infra", Auth: []ssh.AuthMethod{ssh.PublicKeys(s)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
				if err != nil {
					continue
				}
				if sess, err := c.NewSession(); err == nil {
					var out bytes.Buffer
					sess.Stdout = &out
					_ = sess.Run("cert stored.example.org")
					if s == signer && !strings.Contains(out.String(), "PRIVATE KEY") {
						t.Errorf("the owner did not get its certificate: %q", out.String())
					}
				}
				c.Close()
			}
			waitFor(t, logs, "connection denied")
			waitFor(t, logs, "cert served")
			waitFor(t, logs, "certificate attempt failed") // new.example.org: the CA is unreachable
			cancel()
			<-done
			out := logs.String()
			for what, secret := range map[string]string{"Cloudflare token": cfToken, "certificate key": keyBody, "key header": "PRIVATE KEY", "host key": strings.TrimSpace(string(hostKey))} {
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
