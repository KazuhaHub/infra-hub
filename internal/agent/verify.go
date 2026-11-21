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

	"filippo.io/age"
	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/KazuhaHub/infra-hub/internal/bundle"
	"github.com/KazuhaHub/infra-hub/internal/sigstorever"
)

// RejectError is a bundle that fails a check (signature, hash, format): the cycle result is "rejected".
type RejectError struct{ Reason string }

func (e *RejectError) Error() string { return e.Reason }

func rejectf(format string, a ...any) error { return &RejectError{Reason: fmt.Sprintf(format, a...)} }

// maxPlain bounds the decrypted archive: four members, their headers and the end marker.
const maxPlain = bundle.MaxTarball + bundle.MaxStatement + bundle.MaxSignature + bundle.MaxSigstore + 16<<10

// OpenBundle decrypts the hub's answer and returns the files. The archive holds bundle, then bundle.sig if the hub is
// older than v0.15.0 (read and ignored), bundle.tar.gz and bundle.sigstore.json, in that order, each a regular file
// within its limit, and nothing else. A missing bundle.sigstore.json is not an error here: verification rejects it.
func OpenBundle(ciphertext io.Reader, id *Identity) (bundle.Files, error) {
	var f bundle.Files
	pr, err := age.Decrypt(ciphertext, id.ids...)
	if err != nil {
		return f, rejectf("cannot decrypt the bundle with this host's age key")
	}
	plain := &capReader{r: pr, left: maxPlain}
	tr := tar.NewReader(plain)
	order := []struct {
		name     string
		limit    int64
		dst      *[]byte
		optional bool
	}{
		{bundle.StatementName, bundle.MaxStatement, &f.Statement, false},
		{bundle.SignatureName, bundle.MaxSignature, &f.Signature, true},
		{bundle.TarballName, bundle.MaxTarball, &f.Tarball, false},
		{bundle.SigstoreName, bundle.MaxSigstore, &f.Sigstore, true},
	}
	next := 0 // the first entry of order that the next member may be
	var h *tar.Header
	for {
		h, err = tr.Next()
		if err != nil {
			break
		}
		i := next
		for i < len(order) && order[i].name != h.Name {
			if !order[i].optional {
				break
			}
			i++
		}
		if i >= len(order) || order[i].name != h.Name {
			if next < len(order) && !order[next].optional {
				return f, rejectf("the bundle archive has member %q where %q is expected", h.Name, order[next].name)
			}
			return f, rejectf("the bundle archive has unexpected member %q", h.Name)
		}
		m := order[i]
		next = i + 1
		if h.Typeflag != tar.TypeReg {
			return f, rejectf("bundle member %s is not a regular file", m.name)
		}
		if h.Size < 0 || h.Size > m.limit {
			return f, rejectf("bundle member %s is larger than %d bytes", m.name, m.limit)
		}
		data, rerr := io.ReadAll(io.LimitReader(tr, m.limit+1))
		if rerr != nil || int64(len(data)) != h.Size {
			return f, rejectf("bundle member %s cannot be read: %v", m.name, plainErr(rerr))
		}
		*m.dst = data
	}
	if err != io.EOF {
		if f.Statement == nil || f.Tarball == nil {
			return f, rejectf("the bundle archive is incomplete: %v", plainErr(err))
		}
		return f, rejectf("the bundle archive cannot be read: %v", err)
	}
	if f.Statement == nil {
		return f, rejectf("the bundle archive is missing %s", bundle.StatementName)
	}
	if f.Tarball == nil {
		return f, rejectf("the bundle archive is missing %s", bundle.TarballName)
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
	f.Signature = nil // the legacy ssh signature is not used
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
		tr, info, err := a.SigstoreTUF.Root(ctx)
		if err != nil {
			return nil, err
		}
		if info.Fallback {
			a.rootNote = "WARNING sigstore root: " + sigstorever.InfoText(info)
			slog.Warn("the Sigstore trusted root is the embedded one", "note", a.rootNote)
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

// verifyFiles checks the Sigstore signature of the statement and returns SigSigstore. The legacy ssh signature is not
// looked at.
func (a *Agent) verifyFiles(ctx context.Context, files bundle.Files) (string, error) {
	if err := a.verifySigstore(ctx, files); err != nil {
		return "", err
	}
	return SigSigstore, nil
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
