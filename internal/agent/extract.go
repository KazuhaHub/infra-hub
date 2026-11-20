package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Limits of an extraction.
const (
	// MaxExtracted bounds the decompressed size of the tarball (headers included).
	MaxExtracted = 512 << 20
	maxEntries   = 200000
	// KeepReleases is how many extracted releases are kept.
	KeepReleases = 3
)

// ReleaseDir is where the release of commit lives.
func ReleaseDir(stateDir, commit string) string { return filepath.Join(stateDir, "releases", commit) }

// extractLimit is MaxExtracted (a variable so that a test can lower it).
var extractLimit int64 = MaxExtracted

// Extract unpacks the gzip tar into <state>/releases/<commit>: first into a temporary directory next to it, then renamed
// into place, so a release directory is always complete. An existing release of the same commit is replaced.
func Extract(stateDir, commit string, tarball []byte) (string, error) {
	rel := filepath.Join(stateDir, "releases")
	if err := os.MkdirAll(rel, 0o700); err != nil {
		return "", err
	}
	tmp, err := os.MkdirTemp(rel, ".tmp-"+commit[:12]+"-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	if err := ExtractTar(tmp, bytes.NewReader(tarball)); err != nil {
		return "", err
	}
	if st, err := os.Stat(filepath.Join(tmp, "infra")); err != nil || !st.IsDir() {
		return "", rejectf("the bundle has no infra/ directory")
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return "", err
	}
	final := ReleaseDir(stateDir, commit)
	if err := os.RemoveAll(final); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, final); err != nil {
		return "", err
	}
	now := time.Now()
	_ = os.Chtimes(final, now, now) // the order of the releases (for pruning) is the order of extraction
	return final, nil
}

// PruneReleases removes all but the newest keep releases, and leftover temporary directories. The releases named in
// protect are never removed.
func PruneReleases(stateDir string, keep int, protect ...string) error {
	rel := filepath.Join(stateDir, "releases")
	entries, err := os.ReadDir(rel)
	if err != nil {
		return err
	}
	type r struct {
		name string
		mod  time.Time
	}
	var rs []r
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			os.RemoveAll(filepath.Join(rel, e.Name()))
			continue
		}
		if !e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		rs = append(rs, r{e.Name(), info.ModTime()})
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].mod.After(rs[j].mod) })
	var firstErr error
	for i, x := range rs {
		if i < keep || contains(protect, x.name) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(rel, x.name)); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// ExtractTar unpacks a gzip tar into the existing directory dst. It refuses absolute paths, "..", a path that passes
// through a symlink the archive made, symlinks and hard links that point outside, devices, FIFOs and anything of an
// unknown type, and stops at MaxExtracted decompressed bytes. Files keep their permission bits (no setuid, setgid or
// sticky) and are owned by the user that runs the agent. os.Root is a second guard: no operation can leave dst.
func ExtractTar(dst string, r io.Reader) error {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return rejectf("bundle.tar.gz is not gzip: %v", err)
	}
	defer zr.Close()
	root, err := os.OpenRoot(dst)
	if err != nil {
		return err
	}
	defer root.Close()
	tr := tar.NewReader(&limitedReader{r: zr, left: extractLimit})
	symlinks := map[string]bool{}
	files := map[string]bool{} // regular files already made (hard link targets)
	n := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return rejectf("bundle.tar.gz: %v", err)
		}
		if h.Typeflag == tar.TypeXGlobalHeader { // git archive's comment header
			continue
		}
		if n++; n > maxEntries {
			return rejectf("bundle.tar.gz has too many entries")
		}
		name, err := cleanMember(h.Name)
		if err != nil {
			return err
		}
		if name == "." { // the archive's root entry
			if h.Typeflag != tar.TypeDir {
				return rejectf("bundle entry %q is not a directory", h.Name)
			}
			continue
		}
		if under(symlinks, name) {
			return rejectf("bundle entry %q passes through a symlink", h.Name)
		}
		if symlinks[name] {
			return rejectf("bundle entry %q appears twice", h.Name)
		}
		perm := fs.FileMode(h.Mode) & 0o777
		switch h.Typeflag {
		case tar.TypeDir:
			if err := mkdirAll(root, name); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := mkdirAll(root, path.Dir(name)); err != nil {
				return err
			}
			if files[name] || symlinks[name] {
				return rejectf("bundle entry %q appears twice", h.Name)
			}
			f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm|0o400)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return rejectf("bundle entry %q: %v", h.Name, err)
			}
			if err := f.Close(); err != nil {
				return err
			}
			if err := root.Chmod(name, perm|0o400); err != nil {
				return err
			}
			files[name] = true
		case tar.TypeSymlink:
			if err := checkSymlink(name, h.Linkname); err != nil {
				return err
			}
			if err := mkdirAll(root, path.Dir(name)); err != nil {
				return err
			}
			if err := root.Symlink(h.Linkname, name); err != nil {
				return err
			}
			symlinks[name] = true
		case tar.TypeLink:
			target, err := cleanMember(h.Linkname)
			if err != nil || target == "." || under(symlinks, target) || !files[target] {
				return rejectf("bundle hard link %q points to %q, which is not a file of the archive", h.Name, h.Linkname)
			}
			if err := mkdirAll(root, path.Dir(name)); err != nil {
				return err
			}
			if err := root.Link(target, name); err != nil {
				return err
			}
			files[name] = true
		default:
			return rejectf("bundle entry %q has a type that is not allowed (%q): only files, directories and links are", h.Name, string(h.Typeflag))
		}
	}
	return nil
}

// cleanMember checks a member name and returns it in clean, relative, slash form ("." for the root).
func cleanMember(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, 0) || strings.ContainsRune(name, '\\') {
		return "", rejectf("bundle entry name %q is not allowed", name)
	}
	if strings.HasPrefix(name, "/") {
		return "", rejectf("bundle entry %q is an absolute path", name)
	}
	for _, c := range strings.Split(name, "/") {
		if c == ".." {
			return "", rejectf("bundle entry %q contains ..", name)
		}
	}
	return path.Clean(name), nil
}

// checkSymlink accepts a relative target made of any number of leading "../" that stay inside the tree (counted from the
// link's directory), followed by names without "..": the target can then be resolved without leaving the tree even when
// it passes through other links of the archive.
func checkSymlink(name, target string) error {
	bad := rejectf("bundle symlink %q points to %q, outside the tree", name, target)
	if target == "" || strings.HasPrefix(target, "/") || strings.ContainsRune(target, 0) {
		return bad
	}
	parts := strings.Split(target, "/")
	depth := strings.Count(name, "/") // directories above the link
	i := 0
	for i < len(parts) && parts[i] == ".." {
		i++
	}
	if i > depth {
		return bad
	}
	for _, p := range parts[i:] {
		if p == ".." {
			return bad
		}
	}
	return nil
}

// under reports whether name is below a symlink recorded in links.
func under(links map[string]bool, name string) bool {
	for p := path.Dir(name); p != "." && p != "/"; p = path.Dir(p) {
		if links[p] {
			return true
		}
	}
	return false
}

func mkdirAll(root *os.Root, name string) error {
	if name == "." {
		return nil
	}
	if err := root.MkdirAll(name, 0o755); err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) {
			return rejectf("cannot create directory %s: %v", name, pe.Err)
		}
		return err
	}
	return nil
}

type limitedReader struct {
	r    io.Reader
	left int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.left <= 0 {
		return 0, rejectf("the tarball is larger than %d MiB when unpacked", extractLimit>>20)
	}
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	n, err := l.r.Read(p)
	l.left -= int64(n)
	return n, err
}
