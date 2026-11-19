package httpsapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/hubkey"
	"github.com/KazuhaHub/infra-hub/internal/hubtrust"
)

// runHTTPS starts the Runner with key on a free port and returns its address.
func runHTTPS(t *testing.T, h *testHub, key []byte) string {
	t.Helper()
	k, err := hubkey.Parse(key)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	addrCh := make(chan string, 1)
	r := &Runner{Key: k, Addresses: []string{"hub.example.org"}, Listen: "127.0.0.1:0", Server: h.s,
		OnListen: func(a net.Addr) { addrCh <- a.String() }}
	go r.Run(ctx)
	select {
	case a := <-addrCh:
		return a
	case <-time.After(5 * time.Second):
		t.Fatal("the hub did not serve HTTPS")
		return ""
	}
}

func clientFor(pins ...string) *http.Client {
	v := hubtrust.Verifier{Pins: pins}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: v.TLSConfig()}, Timeout: 5 * time.Second}
}

func TestHTTPSServesToAClientThatPinsTheHubKey(t *testing.T) {
	key, err := hubkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	pem, _ := hubkey.Marshal(key)
	pin, _ := hubkey.Pin(key)
	h := newHub(t)
	addr := runHTTPS(t, h, pem)

	resp, err := clientFor(pin).Get("https://" + addr + "/v1/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]string
	json.NewDecoder(resp.Body).Decode(&doc)
	if resp.StatusCode != 200 || doc["status"] != "ok" || doc["apiVersion"] != "v1" || resp.TLS.Version != tls.VersionTLS13 {
		t.Errorf("healthz: %d %v tls=%x", resp.StatusCode, doc, resp.TLS.Version)
	}
	if n := len(resp.TLS.PeerCertificates); n != 1 {
		t.Errorf("the hub presented %d certificates, want 1", n)
	}

	// A rotation pin list works: the old pin and the right one.
	other, _ := hubkey.Generate()
	otherPin, _ := hubkey.Pin(other)
	if r, err := clientFor(otherPin, pin).Get("https://" + addr + "/v1/healthz"); err != nil {
		t.Errorf("two pins: %v", err)
	} else {
		r.Body.Close()
	}

	// A wrong pin is a TLS failure.
	if _, err := clientFor(otherPin).Get("https://" + addr + "/v1/healthz"); err == nil {
		t.Error("a client with the wrong pin trusted the hub")
	}
	// The system roots do not decide: an ordinary client refuses the self-signed certificate.
	plain := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{ServerName: "hub.example.org"}}}
	if _, err := plain.Get("https://" + addr + "/v1/healthz"); err == nil {
		t.Error("a client with the system roots accepted the hub")
	}
	// TLS 1.2 is refused.
	old := hubtrust.Verifier{Pins: []string{pin}}.TLSConfig()
	old.MinVersion, old.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	if _, err := (&http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: old}}).Get("https://" + addr + "/v1/healthz"); err == nil {
		t.Error("a TLS 1.2 client was served")
	}

	// A challenge and report round trip over TLS.
	c := clientFor(pin)
	cr, err := c.Post("https://"+addr+"/v1/challenge", "application/json", strings.NewReader(`{"host":"h1"}`))
	if err != nil {
		t.Fatal(err)
	}
	var ch map[string]string
	json.NewDecoder(cr.Body).Decode(&ch)
	cr.Body.Close()
	nonce := decryptChallenge(t, h.ids["h1"], ch["challenge"])
	rr, err := c.Post("https://"+addr+"/v1/report", "application/json", strings.NewReader(reportBodyFor("h1", nonce, goodReport)))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(rr.Body)
	rr.Body.Close()
	if rr.StatusCode != 200 {
		t.Errorf("report over TLS: %d %s", rr.StatusCode, body)
	}
}

// Two hubs with the same key have the same pin, so one pin serves every hub.
func TestHubsWithTheSameKeyShareAPin(t *testing.T) {
	key, _ := hubkey.Generate()
	pem, _ := hubkey.Marshal(key)
	pin, _ := hubkey.Pin(key)
	a, b := runHTTPS(t, newHub(t), pem), runHTTPS(t, newHub(t), pem)
	for _, addr := range []string{a, b} {
		r, err := clientFor(pin).Get("https://" + addr + "/v1/healthz")
		if err != nil {
			t.Fatalf("%s: %v", addr, err)
		}
		r.Body.Close()
	}
}
