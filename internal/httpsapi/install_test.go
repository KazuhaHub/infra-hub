package httpsapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func serveInstall(t *testing.T) []byte {
	t.Helper()
	h := newHub(t)
	srv := httptest.NewServer(h.s.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/install")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") ||
		resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v", resp.StatusCode, resp.Header)
	}
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return buf.Bytes()
}

func writeScript(t *testing.T, body []byte) string {
	t.Helper()
	p := t.TempDir() + "/install.sh"
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestInstallIsServedAndParses(t *testing.T) {
	body := serveInstall(t)
	if !bytes.HasPrefix(body, []byte("#!/bin/sh\n")) {
		t.Fatalf("not a sh script: %.40q", body)
	}
	p := writeScript(t, body)
	for _, sh := range []string{"sh", "dash", "bash"} {
		path, err := exec.LookPath(sh)
		if err != nil {
			continue
		}
		args := []string{"-n", p}
		if sh == "bash" {
			args = []string{"--posix", "-n", p}
		}
		if out, err := exec.Command(path, args...).CombinedOutput(); err != nil {
			t.Errorf("%s -n: %v: %s", sh, err, out)
		}
	}
	if path, err := exec.LookPath("shellcheck"); err == nil {
		if out, err := exec.Command(path, "-s", "sh", p).CombinedOutput(); err != nil {
			t.Errorf("shellcheck: %v\n%s", err, out)
		}
	} else {
		t.Log("shellcheck is not installed; skipped")
	}
}

func TestInstallHoldsNoSecretAndNoHubDetails(t *testing.T) {
	s := string(serveInstall(t))
	for _, bad := range []string{"BEGIN ", "AGE-SECRET-KEY", "cloudflare", "ih1.ey"} {
		if strings.Contains(s, bad) {
			t.Errorf("the script contains %q", bad)
		}
	}
}

// The unit the script writes is the documented one, apart from the path of the binary.
func TestInstallEmbedsTheDocumentedUnit(t *testing.T) {
	unit, err := os.ReadFile("../../docs/infra-agent.service")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(installScript, append([]byte("<<'UNIT'\n"), unit...)) {
		t.Error("the unit in install.sh differs from docs/infra-agent.service; copy it in again")
	}
}

func TestInstallHeadAndMethods(t *testing.T) {
	h := newHub(t)
	if code, _ := h.do(t, "POST", "/install", ""); code != 405 {
		t.Errorf("POST: %d", code)
	}
	req := httptest.NewRequest("HEAD", "https://hub.example.org/install", nil)
	rec := httptest.NewRecorder()
	h.s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Body.Len() != 0 || rec.Header().Get("Content-Length") == "" {
		t.Errorf("HEAD: %d %d bytes", rec.Code, rec.Body.Len())
	}
	// rate limit per peer
	var last int
	for i := 0; i < 12; i++ {
		r := httptest.NewRequest("GET", "https://hub.example.org/install", nil)
		rc := httptest.NewRecorder()
		h.s.Handler().ServeHTTP(rc, r)
		last = rc.Code
	}
	if last != 429 {
		t.Errorf("12 quick requests: last status %d", last)
	}
}

// Without root the script must stop on its arguments or on the root check before it changes anything.
func TestInstallRefusesBadInput(t *testing.T) {
	p := writeScript(t, installScript)
	good := "ih1." + strings.Repeat("A", 40)
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"no arguments", nil, 2},
		{"no host", []string{good}, 2},
		{"unknown flag", []string{good, "web1", "--frobnicate"}, 2},
		{"not a token", []string{"hello", "web1"}, 1},
		{"bad host name", []string{good, "web 1;rm"}, 1},
		{"leading dash host", []string{good, "-x"}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "sh", append([]string{p}, c.args...)...)
			cmd.Stdin = nil
			out, err := cmd.CombinedOutput()
			code := 0
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if code != c.want {
				t.Errorf("exit %d, want %d: %s", code, c.want, out)
			}
		})
	}
	if os.Getuid() != 0 {
		out, err := exec.Command("sh", p, good, "web1").CombinedOutput()
		if err == nil || !strings.Contains(string(out), "run as root") {
			t.Errorf("as a normal user: %v %s", err, out)
		}
		if _, err := os.Stat("/etc/infra/agent.env.bak"); err == nil {
			t.Error("something was written")
		}
	}
}
