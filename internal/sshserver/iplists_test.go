package sshserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/KazuhaHub/infra-hub/internal/iplists"
)

// ipManager returns a manager with one provider "cdn" (10 public /24s, served over plain HTTP by a test server) and
// the lists cdn (host-a, plus one manual entry) and cdn2 (host-b). It has not refreshed yet.
func ipManager(t *testing.T) *iplists.IPManager {
	t.Helper()
	var body strings.Builder
	for i := 1; i <= 10; i++ {
		fmt.Fprintf(&body, "11.%d.0.0/24\n", i)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body.String()) }))
	t.Cleanup(srv.Close)
	return &iplists.IPManager{
		Dir:     filepath.Join(t.TempDir(), "iplists"),
		Sources: map[string]iplists.IPSource{"cdn": {URL: srv.URL, Format: "lines"}},
		Lists: map[string]iplists.IPList{
			"cdn":  {Providers: []string{"cdn"}, Manual: []string{"203.0.114.0/24"}, Hosts: []string{"host-a"}},
			"cdn2": {Providers: []string{"cdn"}, Hosts: []string{"host-b"}},
		},
		Now:    func() time.Time { return time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC) },
		Client: &http.Client{Timeout: 300 * time.Millisecond},
	}
}

func ipHub(t *testing.T, m *iplists.IPManager) *testHub {
	return startHub(t, func(h *testHub) { h.srv.IPLists = m })
}

func TestIPListOverSSHIsStrictJSONForAllowedHostsOnly(t *testing.T) {
	m := ipManager(t)
	m.Refresh(context.Background(), "cdn")
	h := ipHub(t, m)

	out, _, err := runCert(t, h, "host-a", "iplist cdn")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(out, "\n") || strings.Count(out, "\n") != 1 {
		t.Fatalf("not exactly one line: %q", out)
	}
	dec := json.NewDecoder(strings.NewReader(out))
	dec.DisallowUnknownFields()
	var p iplists.IPListPayload
	if err := dec.Decode(&p); err != nil {
		t.Fatal(err)
	}
	if p.Name != "cdn" || len(p.CIDRs) != 11 || p.Version != iplists.ListVersion(p.CIDRs) {
		t.Fatalf("%+v", p)
	}
	var raw map[string]any
	json.Unmarshal([]byte(out), &raw)
	if len(raw) != 5 || raw["warnings"] == nil {
		t.Fatalf("keys: %v", raw)
	}

	// refusals look alike: other host, unknown list, other host's list, odd names, injection
	var first string
	for i, c := range []struct{ host, cmd string }{
		{"host-b", "iplist cdn"},
		{"host-a", "iplist nope"},
		{"host-a", "iplist cdn2"},
		{"host-a", "iplist CDN"},
		{"host-a", "iplist ../cdn"},
		{"host-a", "iplist cdn x"},
		{"host-a", "iplist cdn; id"},
		{"host-a", "iplist"},
		{"host-a", "iplist  cdn"},
	} {
		_, _, err := runCert(t, h, c.host, c.cmd)
		if err == nil {
			t.Errorf("%s %q was served", c.host, c.cmd)
			continue
		}
		msg := strings.Replace(err.Error(), c.cmd, "<cmd>", 1)
		if i == 0 {
			first = msg
		} else if msg != first {
			t.Errorf("%s %q: refusal %q differs from %q", c.host, c.cmd, msg, first)
		}
	}
}

func TestIPListNotReadyIsRefusedWithExit1(t *testing.T) {
	h := ipHub(t, ipManager(t)) // nothing refreshed yet
	out, errOut, err := runCert(t, h, "host-a", "iplist cdn")
	var ee *ssh.ExitError
	if !errors.As(err, &ee) || ee.ExitStatus() != 1 || out != "" || !strings.Contains(errOut, "not delivered") {
		t.Fatalf("err=%v out=%q stderr=%q", err, out, errOut)
	}
}

func TestIPListWithoutAManagerIsRefused(t *testing.T) {
	h := startHub(t)
	if _, _, err := runCert(t, h, "host-a", "iplist cdn"); err == nil {
		t.Fatal("served with no list source")
	}
}

func TestIPListUsesTheSlotLimitsAndIgnoresStaleMirror(t *testing.T) {
	m := ipManager(t)
	m.Refresh(context.Background(), "cdn")
	h := ipHub(t, m)
	h.srv.Fresh = func() error { return errors.New("mirror too old") }
	h.srv.PerHostMax = 0
	if _, _, err := runCert(t, h, "host-a", "iplist cdn"); err == nil {
		t.Fatal("the per-host limit does not apply to iplist")
	}
	h.srv.PerHostMax = 2
	for i := 0; i < 5; i++ {
		if _, _, err := runCert(t, h, "host-a", "iplist cdn"); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
}
