package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/KazuhaHub/infra-hub/internal/config"
)

func TestStatusWithNoRefsRunsNoGit(t *testing.T) {
	bin := t.TempDir()
	marker := filepath.Join(bin, "git-ran")
	os.WriteFile(filepath.Join(bin, "git"), []byte("#!/bin/sh\ntouch "+marker+"\necho 'abc refs/heads/main'\n"), 0o755)
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	cfg := config.Config{Repo: "/x/infra.git", State: filepath.Join(t.TempDir(), "s.json"), Clients: map[string]string{"h": ""}, CertDir: t.TempDir()}
	out, _ := os.Create(filepath.Join(t.TempDir(), "out"))
	defer out.Close()
	if err := status(cfg, out, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("git ran with no-refs")
	}
	if err := status(cfg, out, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("git did not run without no-refs")
	}
}
