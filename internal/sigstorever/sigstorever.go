// Package sigstorever verifies the keyless Sigstore signature of the bundle statement (docs/bundle.md, "bundle.sigstore.json"):
// a Sigstore bundle made by cosign in the GitHub Actions workflow of the infra repository, checked offline against a
// public-good trusted root that is embedded in the binary (trusted_root.json; docs/agent.md says how a release refreshes it).
package sigstorever

import (
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
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
// workflow reference (it is also the certificate's build signer URI). It is the same whatever event started the run (push, schedule, workflow_dispatch); the event is a
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

// Policy is what the signing certificate must say.
type Policy struct {
	// Repo is owner/name of the infra repository; RepoID and OwnerID are the numeric GitHub IDs of the repository and of
	// its owner (a renamed or re-created repository, or a new owner of the same name, has other IDs).
	Repo, RepoID, OwnerID string
	// Commit, when not empty, is the commit the certificate must name as the source digest (the statement's commit).
	Commit string
	// Relaxed skips the checks that a throwaway Sigstore cannot satisfy (the certificate extensions beyond the issuer and
	// the subject name, and the certificate timestamp). Tests only: the agent sets it only when it was given a test root.
	Relaxed bool
}

// Verify checks that bundleJSON is a Sigstore bundle by the infra workflow over statement: the signature and the
// certificate chain against tm; the OIDC issuer and exactly the subject alternative name of Identity(p.Repo); the
// certificate's source repository, ref, owner, IDs, build signer and runner (a GitHub-hosted one); at least one Rekor
// entry with a verified timestamp; a signed certificate timestamp (SCT); and a signed digest equal to the sha256 of
// statement. Every error is a reason to reject the bundle.
func Verify(tm root.TrustedMaterial, bundleJSON, statement []byte, p Policy) (*Result, error) {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return nil, fmt.Errorf("not a valid Sigstore bundle: %w", err)
	}
	opts := []verify.VerifierOption{verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1)}
	if !p.Relaxed {
		opts = append(opts, verify.WithSignedCertificateTimestamps(1))
	}
	v, err := verify.NewVerifier(tm, opts...)
	if err != nil {
		return nil, err
	}
	identity := Identity(p.Repo)
	var ext certificate.Extensions
	if !p.Relaxed {
		owner, _, _ := strings.Cut(p.Repo, "/")
		ext = certificate.Extensions{
			GithubWorkflowRepository:        p.Repo,
			SourceRepositoryURI:             "https://github.com/" + p.Repo,
			SourceRepositoryRef:             Ref,
			SourceRepositoryOwnerURI:        "https://github.com/" + owner,
			SourceRepositoryIdentifier:      p.RepoID,
			SourceRepositoryOwnerIdentifier: p.OwnerID,
			BuildSignerURI:                  identity,
			RunnerEnvironment:               "github-hosted",
			SourceRepositoryDigest:          p.Commit,
		}
	}
	sanM, err := verify.NewSANMatcher(identity, "")
	if err != nil {
		return nil, err
	}
	issM, err := verify.NewIssuerMatcher(Issuer, "")
	if err != nil {
		return nil, err
	}
	cid, err := verify.NewCertificateIdentity(sanM, issM, ext)
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
