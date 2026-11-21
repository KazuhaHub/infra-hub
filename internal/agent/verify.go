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
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/KazuhaHub/infra-hub/internal/bundle"
	"github.com/KazuhaHub/infra-hub/internal/sigstorever"
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

// maxPlain bounds the decrypted archive: four members, their headers and the end marker.
const maxPlain = bundle.MaxTarball + bundle.MaxStatement + bundle.MaxSignature + bundle.MaxSigstore + 16<<10

// OpenBundle decrypts the hub's answer and returns the files. The archive must hold bundle, bundle.sig and
// bundle.tar.gz, in that order, and then optionally bundle.sigstore.json (a hub answers with it only to a request for
// format 2), each a regular file within its limit, and nothing else.
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
	h, err := tr.Next()
	if err == nil {
		if h.Name != bundle.SigstoreName {
			return f, rejectf("the bundle archive has member %q where only %s may follow the three files", h.Name, bundle.SigstoreName)
		}
		if h.Typeflag != tar.TypeReg {
			return f, rejectf("bundle member %s is not a regular file", h.Name)
		}
		if h.Size < 0 || h.Size > bundle.MaxSigstore {
			return f, rejectf("bundle member %s is larger than %d bytes", h.Name, bundle.MaxSigstore)
		}
		data, rerr := io.ReadAll(io.LimitReader(tr, bundle.MaxSigstore+1))
		if rerr != nil || int64(len(data)) != h.Size {
			return f, rejectf("bundle member %s cannot be read: %v", h.Name, plainErr(rerr))
		}
		f.Sigstore = data
		_, err = tr.Next()
	}
	if err != io.EOF {
		return f, rejectf("the bundle archive has more members than it may hold")
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

// sigstoreMaterial is the trusted material for Sigstore verification: the injected one (tests), the root the TUF manager
// keeps current, or the embedded root.
func (a *Agent) sigstoreMaterial(ctx context.Context) (root.TrustedMaterial, error) {
	if a.SigstoreRoot != nil {
		return a.SigstoreRoot, nil
	}
	if a.SigstoreTUF != nil {
		tr, _, err := a.SigstoreTUF.Root(ctx)
		if err != nil {
			return nil, err
		}
		return tr, nil
	}
	tr, err := sigstorever.EmbeddedRoot()
	if err != nil {
		return nil, err
	}
	return tr, nil
}

// verifySigstore checks bundle.sigstore.json against the statement and the identity of the infra workflow.
func (a *Agent) verifySigstore(ctx context.Context, files bundle.Files) error {
	if len(files.Sigstore) == 0 {
		return rejectf("the bundle has no %s (the Sigstore signature)", bundle.SigstoreName)
	}
	tm, err := a.sigstoreMaterial(ctx)
	if err != nil {
		return err // this machine's fault: not a reason to call the bundle bad
	}
	pol := sigstorever.Policy{Repo: a.Cfg.Repo, RepoID: a.Cfg.SigstoreRepoID, OwnerID: a.Cfg.SigstoreOwnerID,
		Relaxed: a.SigstoreRoot != nil} // only a test root is relaxed
	if st, err := bundle.ParseStatement(files.Statement); err == nil {
		pol.Commit = st.Commit // the workflow run that signed must be the one that built this commit
	}
	res, err := sigstorever.Verify(tm, files.Sigstore, files.Statement, pol)
	if err != nil {
		return rejectf("the Sigstore signature in %s does not verify: %v", bundle.SigstoreName, err)
	}
	slog.Debug("Sigstore signature verified", "identity", res.Identity, "issuer", res.Issuer, "loggedAt", res.Time)
	return nil
}

// verifyFiles applies the signature mode and returns the signature that verified the statement (SigSSH or
// SigSigstore). In either mode a Sigstore signature that is there is tried first, and a bad one does not stop a good ssh
// signature from being accepted.
func (a *Agent) verifyFiles(ctx context.Context, files bundle.Files) (string, error) {
	sshCheck := func() error {
		return VerifySignature(ctx, a.SSHKeygen, a.Cfg.Signers, a.Cfg.StateDir, files.Statement, files.Signature)
	}
	switch a.Cfg.Signature {
	case SigSigstore:
		if err := a.verifySigstore(ctx, files); err != nil {
			return "", err
		}
		return SigSigstore, nil
	case SigEither:
		var sErr error
		if len(files.Sigstore) > 0 {
			if sErr = a.verifySigstore(ctx, files); sErr == nil {
				return SigSigstore, nil
			}
			var rj *RejectError
			if !errors.As(sErr, &rj) {
				return "", sErr
			}
		}
		err := sshCheck()
		if err == nil {
			if sErr != nil {
				slog.Warn("the Sigstore signature is bad, accepted the ssh signature", "err", sErr)
				a.sigWarn = strings.TrimPrefix(sErr.Error(), "the Sigstore signature in "+bundle.SigstoreName+" ")
			}
			return SigSSH, nil
		}
		var rj *RejectError
		if sErr != nil && errors.As(err, &rj) {
			return "", rejectf("%s; %s", sErr.Error(), rj.Reason)
		}
		return "", err
	}
	if err := sshCheck(); err != nil {
		return "", err
	}
	return SigSSH, nil
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
