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

// AttestationRef is the branch the files are read from.
const AttestationRef = "refs/heads/main-attestation"

// Limits bounds the files; tests inject smaller ones. A zero Sigstore means MaxSigstore.
type Limits struct {
	Tarball, Statement, Signature, Sigstore int64
}

// DefaultLimits are the limits of the contract.
var DefaultLimits = Limits{Tarball: MaxTarball, Statement: MaxStatement, Signature: MaxSignature, Sigstore: MaxSigstore}

// ErrNoBundle wraps every reason the hub has no bundle to serve (missing file, over a limit, malformed statement).
var ErrNoBundle = errors.New("no bundle")

func noBundle(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrNoBundle, fmt.Sprintf(format, a...))
}

// ErrFormatUnavailable is a request for an archive format that the files on the branch cannot make (formats 1 and 2
// hold bundle.sig, which the branch no longer has once CI stops signing with the ssh key).
var ErrFormatUnavailable = errors.New("archive format unavailable")

// Files are the files as published. Signature is the legacy bundle.sig: nil when the branch has none (it is only
// needed to serve formats 1 and 2).
type Files struct {
	Statement, Signature, Tarball, Sigstore []byte
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
	out, err := runGit(ctx, repo, 10*time.Second, 1<<10, 0, "rev-parse", "--verify", "--quiet", AttestationRef+"^{commit}")
	if err != nil {
		return "", noBundle("no main-attestation branch in the mirror")
	}
	tip := strings.TrimSpace(string(out))
	if !tipRe.MatchString(tip) {
		return "", noBundle("main-attestation tip is not a commit id")
	}
	return tip, nil
}

// Load reads the statement, the tarball and the Sigstore bundle (all required) and the optional legacy signature at the
// tip of main-attestation. Sizes are checked before content is read and the read itself is capped, so an oversized
// blob is never held in memory. The statement is parsed strictly; the signatures and the hash are not checked (the
// agent does that).
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
	sigMax := lim.Sigstore
	if sigMax == 0 {
		sigMax = MaxSigstore
	}
	for _, f := range []struct {
		name string
		max  int64
		dst  *[]byte
	}{{StatementName, lim.Statement, &l.Files.Statement}, {TarballName, lim.Tarball, &l.Files.Tarball}, {SigstoreName, sigMax, &l.Files.Sigstore}} {
		data, err := readBlob(ctx, repo, tip, f.name, f.max)
		if err != nil {
			return Loaded{}, err
		}
		*f.dst = data
	}
	// The legacy ssh signature is optional and never makes the bundle unusable: one that is missing, not a blob or over
	// its limit is left out (formats 1 and 2 then cannot be served).
	if data, err := readBlob(ctx, repo, tip, SignatureName, lim.Signature); err == nil {
		l.Files.Signature = data
	}
	st, err := ParseStatement(l.Files.Statement)
	if err != nil {
		return Loaded{}, noBundle("%v", err)
	}
	l.Statement = st
	return l, nil
}

// LoadStatement reads and parses only the statement file at tip (with its size check). It reads neither the signature
// nor the tarball.
func LoadStatement(ctx context.Context, repo, tip string, lim Limits) (Statement, error) {
	if !tipRe.MatchString(tip) {
		return Statement{}, noBundle("bad tip")
	}
	data, err := readBlob(ctx, repo, tip, StatementName, lim.Statement)
	if err != nil {
		return Statement{}, err
	}
	st, err := ParseStatement(data)
	if err != nil {
		return Statement{}, noBundle("%v", err)
	}
	return st, nil
}

// Inspect is LoadStatement plus a check that the tarball and the Sigstore bundle exist as files within their limits. It
// reads no content of those two.
func Inspect(ctx context.Context, repo, tip string, lim Limits) (Statement, error) {
	st, err := LoadStatement(ctx, repo, tip, lim)
	if err != nil {
		return Statement{}, err
	}
	for _, f := range []struct {
		name string
		max  int64
	}{{TarballName, lim.Tarball}, {SigstoreName, sigstoreMax(lim)}} {
		if _, err := blobSize(ctx, repo, tip, f.name, f.max); err != nil {
			return Statement{}, err
		}
	}
	return st, nil
}

func sigstoreMax(lim Limits) int64 {
	if lim.Sigstore == 0 {
		return MaxSigstore
	}
	return lim.Sigstore
}

// blobSize checks that name at tip is a blob of at most max bytes and returns its size.
func blobSize(ctx context.Context, repo, tip, name string, max int64) (int64, error) {
	spec := tip + ":" + name // tip is hex and name is one of our constants
	out, err := runGit(ctx, repo, 10*time.Second, 64, 0, "cat-file", "-t", spec)
	if err != nil || strings.TrimSpace(string(out)) != "blob" {
		return 0, noBundle("%s is missing", name)
	}
	out, err = runGit(ctx, repo, 10*time.Second, 64, 0, "cat-file", "-s", spec)
	if err != nil {
		return 0, noBundle("%s is missing", name)
	}
	size, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil || size < 0 {
		return 0, noBundle("%s has no size", name)
	}
	if size > max {
		return 0, noBundle("%s is over its limit (%d bytes)", name, max)
	}
	return size, nil
}

func readBlob(ctx context.Context, repo, tip, name string, max int64) ([]byte, error) {
	size, err := blobSize(ctx, repo, tip, name, max)
	if err != nil {
		return nil, err
	}
	data, err := runGit(ctx, repo, time.Minute, max, size, "cat-file", "blob", tip+":"+name)
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

// runGit (expect is the output size when known) runs git with the hub's clean environment, a timeout and an output cap. Arguments are never interpreted by a
// shell.
func runGit(ctx context.Context, repo string, timeout time.Duration, max, expect int64, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = gitmirror.GitEnv("GIT_DIR=" + repo)
	out := &capWriter{max: max}
	if expect > 0 {
		out.buf.Grow(int(expect)) // one allocation of the right size: no doubling copies
	}
	cmd.Stdout = out
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return out.buf.Bytes(), nil
}

// Archive is the uncompressed POSIX ustar the hub encrypts: the files as regular members in a fixed order, mode 0644,
// uid and gid 0, mtime the statement time, nothing else. Format 1 is bundle, bundle.sig, bundle.tar.gz; format 2 adds
// bundle.sigstore.json; format 3 is bundle, bundle.tar.gz, bundle.sigstore.json. Formats 1 and 2 need bundle.sig and
// fail with ErrFormatUnavailable without it.
func Archive(f Files, mtime time.Time, format int) ([]byte, error) {
	type member struct {
		name string
		data []byte
	}
	var members []member
	switch format {
	case Format1, Format2:
		if len(f.Signature) == 0 {
			return nil, fmt.Errorf("%w: format %d holds %s and the branch has none", ErrFormatUnavailable, format, SignatureName)
		}
		members = []member{{StatementName, f.Statement}, {SignatureName, f.Signature}, {TarballName, f.Tarball}}
		if format == Format2 {
			members = append(members, member{SigstoreName, f.Sigstore})
		}
	case Format3:
		members = []member{{StatementName, f.Statement}, {TarballName, f.Tarball}, {SigstoreName, f.Sigstore}}
	default:
		return nil, fmt.Errorf("%w: format %d", ErrFormatUnavailable, format)
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, m := range members {
		h := &tar.Header{Typeflag: tar.TypeReg, Name: m.name, Mode: 0o644, Size: int64(len(m.data)), ModTime: mtime.UTC(), Format: tar.FormatUSTAR}
		if err := tw.WriteHeader(h); err != nil {
			return nil, noBundle("cannot build the archive: %v", err)
		}
		if _, err := io.Copy(tw, bytes.NewReader(m.data)); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, noBundle("cannot build the archive: %v", err)
	}
	return buf.Bytes(), nil
}
