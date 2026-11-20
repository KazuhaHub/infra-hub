package agent

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// CertOutDir writes the per-hub results of `infra-agent cert --out-dir`: <i>.json for a decrypted reply, <i>.err for
// a one-line reason. The directory is opened with openat2, so no component of its path may be a symlink, and every file is
// created (O_EXCL, mode 0600, owned by the directory's owner) in it under a temporary name and renamed into place,
// so nothing that is already in the directory is ever followed or written through.
type CertOutDir struct {
	f *os.File
}

// OpenCertOutDir opens dir for writing results.
func OpenCertOutDir(dir string) (*CertOutDir, error) {
	// No component of the path may be a symlink (a parent owned by someone else could be swapped for one).
	fd, err := unix.Openat2(unix.AT_FDCWD, dir, &unix.OpenHow{Flags: unix.O_DIRECTORY | unix.O_RDONLY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", dir, err)
	}
	return &CertOutDir{f: os.NewFile(uintptr(fd), dir)}, nil
}

// Close closes the directory.
func (d *CertOutDir) Close() error { return d.f.Close() }

// Clear removes the results of an earlier run for hub index i (a symlink or anything else with that name is
// unlinked, not followed).
func (d *CertOutDir) Clear(i int) error {
	for _, ext := range []string{".json", ".err"} {
		name := strconv.Itoa(i) + ext
		if err := unix.Unlinkat(int(d.f.Fd()), name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			if errors.Is(err, unix.EISDIR) || errors.Is(err, unix.EPERM) {
				err = unix.Unlinkat(int(d.f.Fd()), name, unix.AT_REMOVEDIR)
			}
			if err != nil {
				return fmt.Errorf("remove %s: %w", name, err)
			}
		}
	}
	return nil
}

// Write stores data as <i>.json (ok) or <i>.err (not ok), replacing what is there.
func (d *CertOutDir) Write(i int, ok bool, data []byte) error {
	final := strconv.Itoa(i) + ".err"
	if ok {
		final = strconv.Itoa(i) + ".json"
	}
	st, err := d.f.Stat()
	if err != nil {
		return err
	}
	ds, isStat := st.Sys().(*syscall.Stat_t)
	if !isStat {
		return errors.New("cannot read the owner of the directory")
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := "." + final + ".tmp-" + hex.EncodeToString(rnd[:])
	fd, err := unix.Openat(int(d.f.Fd()), tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	f := os.NewFile(uintptr(fd), tmp)
	done := false
	defer func() {
		f.Close()
		if !done {
			_ = unix.Unlinkat(int(d.f.Fd()), tmp, 0)
		}
	}()
	if err := f.Chown(int(ds.Uid), int(ds.Gid)); err != nil {
		return fmt.Errorf("chown %s: %w", final, err)
	}
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := unix.Renameat(int(d.f.Fd()), tmp, int(d.f.Fd()), final); err != nil {
		return fmt.Errorf("rename to %s: %w", final, err)
	}
	done = true
	return nil
}
