package agentapp

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KazuhaHub/infra-hub/internal/agenttest"
	"github.com/KazuhaHub/infra-hub/internal/certs"
	"github.com/KazuhaHub/infra-hub/internal/hubkey"
)

const certName = "a.example.org"

func certWorld(t *testing.T) (*agenttest.World, *agenttest.StaticCerts) {
	t.Helper()
	w := agenttest.NewWorld(t)
	sc := &agenttest.StaticCerts{Owners: map[string]string{certName: agenttest.Host},
		Payload: certs.CertPayload{Fullchain: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
			Privkey: "-----BEGIN PRIVATE KEY-----\nBBBB\n-----END PRIVATE KEY-----\n", NotAfter: "2027-01-01T00:00:00Z"}}
	w.Certs = sc
	return w, sc
}

func TestCertPrintsTheFirstAnswer(t *testing.T) {
	w, _ := certWorld(t)
	good := w.StartHub()
	dead := agenttest.DeadURL(t)
	envFile := writeEnvFile(t, w, "verify", []string{dead, good.URL}, []string{good.Pin})
	code, out, errs := runAgent(t, nil, "cert", certName, "--env-file", envFile)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var p certs.CertPayload
	if err := json.Unmarshal([]byte(out), &p); err != nil || p.Name != certName || !strings.Contains(p.Privkey, "PRIVATE KEY") || !strings.HasSuffix(out, "\n") {
		t.Fatalf("stdout %q (%v)", out, err)
	}
	if !strings.Contains(errs, "hub ") || strings.Contains(errs, "PRIVATE KEY") {
		t.Errorf("stderr should name the dead hub and carry no secret: %q", errs)
	}
}

func TestCertExitCodes(t *testing.T) {
	w, sc := certWorld(t)
	hub := w.StartHub()
	envFile := writeEnvFile(t, w, "verify", []string{hub.URL}, []string{hub.Pin})

	if code, _, errs := runAgent(t, nil, "cert", certName, "--hub", "https://127.0.0.1:1", "--env-file", envFile); code != 2 || !strings.Contains(errs, "not one of the hubs") {
		t.Errorf("--hub not in the token: exit %d, %q", code, errs)
	}
	if code, _, _ := runAgent(t, nil, "cert", "../x", "--env-file", envFile); code != 2 {
		t.Errorf("bad name: exit %d", code)
	}
	if code, _, _ := runAgent(t, nil, "cert", "--env-file", envFile); code != 2 {
		t.Errorf("no name: exit %d", code)
	}
	if code, _, _ := runAgent(t, nil, "cert", certName, "--env-file", filepath.Join(w.Dir, "missing.env")); code != 2 {
		t.Errorf("no env file: exit %d", code)
	}
	if code, out, _ := runAgent(t, nil, "cert", certName, "--hub", hub.URL, "--env-file", envFile); code != 0 || out == "" {
		t.Errorf("--hub in the token: exit %d", code)
	}

	// Wrong pin: refused, nothing printed.
	other, _ := hubkey.Generate()
	wrong, _ := hubkey.Pin(other)
	bad := writeEnvFile(t, w, "verify", []string{hub.URL}, []string{wrong})
	if code, out, _ := runAgent(t, nil, "cert", certName, "--env-file", bad); code != 1 || out != "" {
		t.Errorf("wrong pin: exit %d, stdout %q", code, out)
	}

	envFile = writeEnvFile(t, w, "verify", []string{hub.URL}, []string{hub.Pin}) // the same path as bad

	// Not the owner: the hub answers 404.
	sc.Owners[certName] = "someone-else"
	if code, out, errs := runAgent(t, nil, "cert", certName, "--env-file", envFile); code != 1 || out != "" || !strings.Contains(errs, "404") {
		t.Errorf("not owner: exit %d, %q, %q", code, out, errs)
	}
	sc.Owners[certName] = agenttest.Host
	sc.Err = errors.New("too close to expiry")
	if code, _, errs := runAgent(t, nil, "cert", certName, "--env-file", envFile); code != 1 || !strings.Contains(errs, "503") {
		t.Errorf("not serving: exit %d, %q", code, errs)
	}
}

func TestCertOversizeIsRefused(t *testing.T) {
	w, sc := certWorld(t)
	sc.Payload.Fullchain = strings.Repeat("A", 2<<20)
	hub := w.StartHub()
	envFile := writeEnvFile(t, w, "verify", []string{hub.URL}, []string{hub.Pin})
	code, out, errs := runAgent(t, nil, "cert", certName, "--env-file", envFile)
	if code != 1 || out != "" || !strings.Contains(errs, "larger than") {
		t.Fatalf("exit %d, stdout %d bytes, %q", code, len(out), errs)
	}
}

func TestCertOutDir(t *testing.T) {
	w, _ := certWorld(t)
	good := w.StartHub()
	dead := agenttest.DeadURL(t)
	envFile := writeEnvFile(t, w, "verify", []string{dead, good.URL}, []string{good.Pin})
	dir := filepath.Join(w.Dir, "out")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(w.Dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Planted: a symlink where 0.err goes, a symlink where 1.json goes, and a stale file.
	if err := os.Symlink(victim, filepath.Join(dir, "0.err")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, "1.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "1.err"), []byte("stale\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	code, out, errs := runAgent(t, nil, "cert", certName, "--out-dir", dir, "--env-file", envFile)
	if code != 0 || out != "" {
		t.Fatalf("exit %d, stdout %q, %s", code, out, errs)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatalf("the symlink target was written: %q", b)
	}
	for name, wantJSON := range map[string]bool{"0.err": false, "1.json": true} {
		st, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", name, st, err)
		}
		b, _ := os.ReadFile(filepath.Join(dir, name))
		if wantJSON {
			var p certs.CertPayload
			if json.Unmarshal(b, &p) != nil || p.Name != certName {
				t.Errorf("%s: %q", name, b)
			}
		} else if strings.Count(string(b), "\n") != 1 || len(b) < 3 {
			t.Errorf("%s: %q", name, b)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "1.err")); !os.IsNotExist(err) {
		t.Errorf("stale 1.err stays: %v", err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 2 {
		t.Errorf("leftovers: %v", ents)
	}

	// The hub that answered before is now the only one asked, and none answers: .err replaces .json, exit 1.
	w.Certs.(*agenttest.StaticCerts).Err = errors.New("x")
	code, _, _ = runAgent(t, nil, "cert", certName, "--out-dir", dir, "--hub", good.URL, "--env-file", envFile)
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	if _, err := os.Lstat(filepath.Join(dir, "1.json")); !os.IsNotExist(err) {
		t.Errorf("stale 1.json stays: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "1.err")); err != nil || !strings.Contains(string(b), "503") {
		t.Errorf("1.err: %q %v", b, err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "0.err")); err != nil {
		t.Errorf("0.err of the hub that was not asked was removed: %v", err)
	}
}

func TestCertOutDirIsNotFollowedWhenItIsASymlink(t *testing.T) {
	w, _ := certWorld(t)
	hub := w.StartHub()
	envFile := writeEnvFile(t, w, "verify", []string{hub.URL}, []string{hub.Pin})
	real := filepath.Join(w.Dir, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(w.Dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	code, _, errs := runAgent(t, nil, "cert", certName, "--out-dir", link, "--env-file", envFile)
	if code != 2 {
		t.Fatalf("exit %d, %s", code, errs)
	}
	if ents, _ := os.ReadDir(real); len(ents) != 0 {
		t.Errorf("wrote through the symlink: %v", ents)
	}
	file := filepath.Join(w.Dir, "plain")
	os.WriteFile(file, nil, 0o600)
	if code, _, _ := runAgent(t, nil, "cert", certName, "--out-dir", file, "--env-file", envFile); code != 2 {
		t.Errorf("a file as out-dir: exit %d", code)
	}
}
