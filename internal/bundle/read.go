package bundle

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/gitmirror"
)

// AttestationRef is the branch the three files are read from.
const AttestationRef = "refs/heads/main-attestation"

// Limits bounds the three files; tests inject smaller ones.
type Limits struct {
	Tarball, Statement, Signature int64
}

// DefaultLimits are the limits of the contract.
var DefaultLimits = Limits{Tarball: MaxTarball, Statement: MaxStatement, Signature: MaxSignature}

// ErrNoBundle wraps every reason the hub has no bundle to serve (missing file, over a limit, malformed statement).
var ErrNoBundle = errors.New("no bundle")

func noBundle(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrNoBundle, fmt.Sprintf(format, a...))
}

// Files are the three files as published.
type Files struct {
	Statement, Signature, Tarball []byte
}

// Loaded is a bundle read from one tip of main-attestation.
type Loaded struct {
	Tip       string // the main-attestation commit the files came from
	Statement Statement
	Files     Files
}

var tipRe = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// Tip returns the commit at the tip of main-attestation. It is cheap, so callers use it to decide whether a cached
// bundle is still current.
func Tip(ctx context.Context, repo string) (string, error) {
	out, err := runGit(ctx, repo, 10*time.Second, 1<<10, "rev-parse", "--verify", "--quiet", AttestationRef+"^{commit}")
	if err != nil {
		return "", noBundle("no main-attestation branch in the mirror")
	}
	tip := strings.TrimSpace(string(out))
	if !tipRe.MatchString(tip) {
		return "", noBundle("main-attestation tip is not a commit id")
	}
	return tip, nil
}

// Load reads the statement, the signature and the tarball at the tip of main-attestation. Sizes are checked before
// content is read and the read itself is capped, so an oversized blob is never held in memory. The statement is
// parsed strictly; the signature and the hash are not checked (the agent does that).
func Load(ctx context.Context, repo string, lim Limits) (Loaded, error) {
	tip, err := Tip(ctx, repo)
	if err != nil {
		return Loaded{}, err
	}
	return LoadAt(ctx, repo, tip, lim)
}

// LoadAt is Load for a tip that was already read.
func LoadAt(ctx context.Context, repo, tip string, lim Limits) (Loaded, error) {
	if !tipRe.MatchString(tip) {
		return Loaded{}, noBundle("bad tip")
	}
	l := Loaded{Tip: tip}
	for _, f := range []struct {
		name string
		max  int64
		dst  *[]byte
	}{{StatementName, lim.Statement, &l.Files.Statement}, {SignatureName, lim.Signature, &l.Files.Signature}, {TarballName, lim.Tarball, &l.Files.Tarball}} {
		data, err := readBlob(ctx, repo, tip, f.name, f.max)
		if err != nil {
			return Loaded{}, err
		}
		*f.dst = data
	}
	st, err := ParseStatement(l.Files.Statement)
	if err != nil {
		return Loaded{}, noBundle("%v", err)
	}
	l.Statement = st
	return l, nil
}

func readBlob(ctx context.Context, repo, tip, name string, max int64) ([]byte, error) {
	spec := tip + ":" + name // tip is hex and name is one of our constants
	out, err := runGit(ctx, repo, 10*time.Second, 64, "cat-file", "-t", spec)
	if err != nil || strings.TrimSpace(string(out)) != "blob" {
		return nil, noBundle("%s is missing", name)
	}
	out, err = runGit(ctx, repo, 10*time.Second, 64, "cat-file", "-s", spec)
	if err != nil {
		return nil, noBundle("%s is missing", name)
	}
	size, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil || size < 0 {
		return nil, noBundle("%s has no size", name)
	}
	if size > max {
		return nil, noBundle("%s is over its limit (%d bytes)", name, max)
	}
	data, err := runGit(ctx, repo, time.Minute, max, "cat-file", "blob", spec)
	if err != nil {
		return nil, noBundle("%s cannot be read", name)
	}
	if int64(len(data)) != size {
		return nil, noBundle("%s changed while it was read", name)
	}
	return data, nil
}

// capWriter keeps at most max bytes and fails the write beyond that.
type capWriter struct {
	buf bytes.Buffer
	max int64
}

var errCap = errors.New("output over the cap")

func (c *capWriter) Write(p []byte) (int, error) {
	if int64(c.buf.Len()+len(p)) > c.max {
		return 0, errCap
	}
	return c.buf.Write(p)
}

// runGit runs git with the hub's clean environment, a timeout and an output cap. Arguments are never interpreted by a
// shell.
func runGit(ctx context.Context, repo string, timeout time.Duration, max int64, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = gitmirror.GitEnv("GIT_DIR=" + repo)
	out := &capWriter{max: max}
	cmd.Stdout = out
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return out.buf.Bytes(), nil
}

// Archive is the uncompressed POSIX ustar the hub encrypts: exactly the three files as regular members in the fixed
// order, mode 0644, uid and gid 0, mtime the statement time, nothing else.
func Archive(f Files, mtime time.Time) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, m := range []struct {
		name string
		data []byte
	}{{StatementName, f.Statement}, {SignatureName, f.Signature}, {TarballName, f.Tarball}} {
		h := &tar.Header{Typeflag: tar.TypeReg, Name: m.name, Mode: 0o644, Size: int64(len(m.data)), ModTime: mtime.UTC(), Format: tar.FormatUSTAR}
		if err := tw.WriteHeader(h); err != nil {
			return nil, err
		}
		if _, err := io.Copy(tw, bytes.NewReader(m.data)); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
