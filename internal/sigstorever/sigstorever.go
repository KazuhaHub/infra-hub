// Package sigstorever verifies the keyless Sigstore signature of the bundle statement (docs/bundle.md, "bundle.sigstore.json"):
// a Sigstore bundle made by cosign in the GitHub Actions workflow of the infra repository, checked offline against a
// public-good trusted root that is embedded in the binary (trusted_root.json; docs/agent.md says how a release refreshes it).
package sigstorever

import (
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// Fixed parts of the signing identity. The workflow file name is part of the contract with the infra repository.
const (
	// Issuer is the OIDC issuer of GitHub Actions; Fulcio records it in the certificate.
	Issuer = "https://token.actions.githubusercontent.com"
	// Workflow is the path of the signing workflow in the infra repository.
	Workflow = ".github/workflows/attest-main.yml"
	// Ref is the only ref the workflow may run on.
	Ref = "refs/heads/main"
)

//go:embed trusted_root.json
var embeddedRoot []byte

var (
	rootOnce sync.Once
	rootVal  *root.TrustedRoot
	rootErr  error
)

// EmbeddedRoot parses the trusted root that is built into the binary (once).
func EmbeddedRoot() (*root.TrustedRoot, error) {
	rootOnce.Do(func() {
		rootVal, rootErr = root.NewTrustedRootFromJSON(embeddedRoot)
		if rootErr != nil {
			rootErr = fmt.Errorf("the embedded Sigstore trusted root does not parse: %w", rootErr)
		}
	})
	return rootVal, rootErr
}

// RootSummary is one line about the embedded trusted root for check-config.
func RootSummary() (string, error) {
	tr, err := EmbeddedRoot()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d certificate authorities, %d transparency logs, %d timestamp authorities", len(tr.FulcioCertificateAuthorities()), len(tr.RekorLogs()), len(tr.TimestampingAuthorities())), nil
}

// Identity is the certificate subject alternative name the signing workflow of repo (owner/name) gets from Fulcio: the
// workflow reference. It is the same whatever event started the run (push, schedule, workflow_dispatch); the event is a
// separate certificate extension.
func Identity(repo string) string {
	return "https://github.com/" + repo + "/" + Workflow + "@" + Ref
}

// Result is what a verified signature says.
type Result struct {
	Identity string    // the certificate's subject alternative name
	Issuer   string    // the OIDC issuer in the certificate
	Time     time.Time // the earliest verified timestamp (the transparency log's integrated time)
}

// Verify checks that bundleJSON is a Sigstore bundle by identity (certificate issuer Issuer and exactly this subject
// alternative name) over statement: the signature and the certificate chain against tm, at least one transparency log
// entry (Rekor) with a verified timestamp, and a signed digest equal to the sha256 of statement. Every error is a
// reason to reject the bundle.
func Verify(tm root.TrustedMaterial, bundleJSON, statement []byte, identity string) (*Result, error) {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return nil, fmt.Errorf("not a valid Sigstore bundle: %w", err)
	}
	v, err := verify.NewVerifier(tm, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	if err != nil {
		return nil, err
	}
	cid, err := verify.NewShortCertificateIdentity(Issuer, "", identity, "")
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(statement)
	res, err := v.Verify(&b, verify.NewPolicy(verify.WithArtifactDigest("sha256", sum[:]), verify.WithCertificateIdentity(cid)))
	if err != nil {
		return nil, err
	}
	out := &Result{Identity: identity, Issuer: Issuer}
	if res.Signature != nil && res.Signature.Certificate != nil {
		out.Identity, out.Issuer = res.Signature.Certificate.SubjectAlternativeName, res.Signature.Certificate.Extensions.Issuer
	}
	for _, ts := range res.VerifiedTimestamps {
		if out.Time.IsZero() || ts.Timestamp.Before(out.Time) {
			out.Time = ts.Timestamp
		}
	}
	if out.Time.IsZero() {
		return nil, errors.New("the Sigstore bundle has no verified timestamp")
	}
	return out, nil
}
