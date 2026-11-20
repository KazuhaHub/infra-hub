package agent

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"filippo.io/age"

	"github.com/KazuhaHub/infra-hub/internal/bundle"
)

// Signature parameters of the contract (docs/bundle.md).
const (
	SignerPrincipal = "infra-main"
	SignerNamespace = "infra-bundle"
	VerifyTimeout   = 30 * time.Second
)

// verifyTimeout is VerifyTimeout (a variable so that a test can lower it).
var verifyTimeout = VerifyTimeout

// RejectError is a bundle that fails a check (signature, hash, format): the cycle result is "rejected".
type RejectError struct{ Reason string }

func (e *RejectError) Error() string { return e.Reason }

func rejectf(format string, a ...any) error { return &RejectError{Reason: fmt.Sprintf(format, a...)} }

// maxPlain bounds the decrypted archive: three members, their headers and the end marker.
const maxPlain = bundle.MaxTarball + bundle.MaxStatement + bundle.MaxSignature + 16<<10

// OpenBundle decrypts the hub's answer and returns the three files. The archive must hold exactly bundle, bundle.sig
// and bundle.tar.gz, in that order, each a regular file within its limit, and nothing else.
func OpenBundle(ciphertext io.Reader, id *Identity) (bundle.Files, error) {
	var f bundle.Files
	pr, err := age.Decrypt(ciphertext, id.ids...)
	if err != nil {
		return f, rejectf("cannot decrypt the bundle with this host's age key")
	}
	plain := &capReader{r: pr, left: maxPlain}
	tr := tar.NewReader(plain)
	members := []struct {
		name  string
		limit int64
		dst   *[]byte
	}{
		{bundle.StatementName, bundle.MaxStatement, &f.Statement},
		{bundle.SignatureName, bundle.MaxSignature, &f.Signature},
		{bundle.TarballName, bundle.MaxTarball, &f.Tarball},
	}
	for _, m := range members {
		h, err := tr.Next()
		if err != nil {
			return f, rejectf("the bundle archive is missing %s: %v", m.name, plainErr(err))
		}
		if h.Name != m.name {
			return f, rejectf("the bundle archive has member %q where %q is expected", h.Name, m.name)
		}
		if h.Typeflag != tar.TypeReg {
			return f, rejectf("bundle member %s is not a regular file", m.name)
		}
		if h.Size < 0 || h.Size > m.limit {
			return f, rejectf("bundle member %s is larger than %d bytes", m.name, m.limit)
		}
		data, err := io.ReadAll(io.LimitReader(tr, m.limit+1))
		if err != nil || int64(len(data)) != h.Size {
			return f, rejectf("bundle member %s cannot be read: %v", m.name, plainErr(err))
		}
		*m.dst = data
	}
	if _, err := tr.Next(); err != io.EOF {
		return f, rejectf("the bundle archive has more members than the three it must hold")
	}
	// Read to the end: age authenticates the stream only when its last chunk has been read, and anything after the
	// archive's end marker must be padding.
	rest, err := io.ReadAll(plain)
	if err != nil {
		return f, rejectf("the bundle is damaged: %v", plainErr(err))
	}
	if len(bytes.Trim(rest, "\x00")) != 0 {
		return f, rejectf("the bundle archive has data after its end")
	}
	return f, nil
}

func plainErr(err error) error {
	if err == nil {
		return errors.New("short data")
	}
	return err
}

// capReader fails when more than left bytes are read.
type capReader struct {
	r    io.Reader
	left int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.left <= 0 {
		var one [1]byte
		if n, _ := c.r.Read(one[:]); n > 0 {
			return 0, errors.New("the decrypted bundle is larger than the limit")
		}
		return 0, io.EOF
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

// VerifySignature runs `ssh-keygen -Y verify` (the tool infra-pull uses) for the statement and its signature against
// the allowed signers file: principal infra-main, namespace infra-bundle. ssh is the program to run ("ssh-keygen").
func VerifySignature(ctx context.Context, ssh, signers, tmpDir string, statement, sig []byte) error {
	dir, err := os.MkdirTemp(tmpDir, ".verify-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	sigPath := filepath.Join(dir, "bundle.sig")
	if err := os.WriteFile(sigPath, sig, 0o600); err != nil {
		return err
	}
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, ssh, "-Y", "verify", "-f", signers, "-I", SignerPrincipal, "-n", SignerNamespace, "-s", sigPath)
	cmd.Stdin = bytes.NewReader(statement)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		if parent.Err() != nil {
			return parent.Err()
		}
		if ctx.Err() != nil {
			return fmt.Errorf("ssh-keygen did not finish in %s", verifyTimeout)
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return rejectf("the bundle signature does not verify (ssh-keygen exit %d)", ee.ExitCode())
		}
		return fmt.Errorf("cannot run %s: %w", ssh, err)
	}
	return nil
}

// CheckStatement parses the statement and checks it against the tarball and the expected repository.
func CheckStatement(raw []byte, repo string, tarball []byte) (bundle.Statement, error) {
	st, err := bundle.ParseStatement(raw)
	if err != nil {
		return st, rejectf("statement: %v", err)
	}
	if st.Repo != repo {
		return st, rejectf("statement repo %q is not %q", st.Repo, repo)
	}
	if st.Ref != "refs/heads/main" {
		return st, rejectf("statement ref %q is not refs/heads/main", st.Ref)
	}
	if st.Size != int64(len(tarball)) {
		return st, rejectf("bundle.tar.gz is %d bytes, the statement says %d", len(tarball), st.Size)
	}
	sum := sha256.Sum256(tarball)
	if hex.EncodeToString(sum[:]) != st.SHA256 {
		return st, rejectf("bundle.tar.gz does not match the sha256 in the statement")
	}
	return st, nil
}
