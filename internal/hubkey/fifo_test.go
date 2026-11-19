//go:build !windows

package hubkey

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO at the key path is refused at once; it must not block the hub (or `key pin`) forever.
func TestReadDoesNotBlockOnAFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("no FIFOs here: %v", err)
	}
	done := make(chan error, 1)
	go func() { _, err := Read(path); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a FIFO was accepted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read blocked on a FIFO")
	}
}
