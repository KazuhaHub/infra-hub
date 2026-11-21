// Package sigstoretest makes Sigstore bundles for tests with a throwaway Sigstore (a certificate authority, a
// transparency log and a timestamp authority that exist only in memory), the way cosign sign-blob --bundle makes them
// with the public-good one. Its trusted material goes where the embedded trusted root would.
package sigstoretest

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor/pkg/types/hashedrekord"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/KazuhaHub/infra-hub/internal/sigstorever"
)

// Fake is one throwaway Sigstore.
type Fake struct {
	t  *testing.T
	vs *ca.VirtualSigstore
}

// New makes a Sigstore with fresh keys.
func New(t *testing.T) *Fake {
	t.Helper()
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	return &Fake{t: t, vs: vs}
}

// TrustedMaterial is the trusted root of this Sigstore.
func (f *Fake) TrustedMaterial() root.TrustedMaterial { return f.vs }

// Options shape a bundle; the zero value is what the infra workflow produces for repo KazuhaHub/infra.
type Options struct {
	// Identity and Issuer are the certificate's subject alternative name and OIDC issuer (default: the workflow of
	// KazuhaHub/infra on main, and GitHub Actions).
	Identity, Issuer string
	// Repo, when set and Identity is empty, gives the default identity for that repository.
	Repo string
	// NoTlog leaves the transparency log entry out of the bundle.
	NoTlog bool
	// Time is the log's integrated time (default shortly after now).
	Time time.Time
}

// Sign returns a Sigstore bundle (protobuf JSON, v0.3) over artifact.
func (f *Fake) Sign(artifact []byte, o Options) []byte {
	f.t.Helper()
	if o.Issuer == "" {
		o.Issuer = sigstorever.Issuer
	}
	if o.Identity == "" {
		repo := o.Repo
		if repo == "" {
			repo = "KazuhaHub/infra"
		}
		o.Identity = sigstorever.Identity(repo)
	}
	if o.Time.IsZero() {
		o.Time = time.Now().Add(time.Minute)
	}
	e, err := f.vs.SignAtTime(o.Identity, o.Issuer, artifact, o.Time)
	if err != nil {
		f.t.Fatal(err)
	}
	vc, err := e.VerificationContent()
	if err != nil {
		f.t.Fatal(err)
	}
	sc, err := e.SignatureContent()
	if err != nil {
		f.t.Fatal(err)
	}
	ms := sc.MessageSignatureContent()
	b := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{Certificate: &protocommon.X509Certificate{RawBytes: vc.Certificate().Raw}},
		},
		Content: &protobundle.Bundle_MessageSignature{MessageSignature: &protocommon.MessageSignature{
			MessageDigest: &protocommon.HashOutput{Algorithm: protocommon.HashAlgorithm_SHA2_256, Digest: ms.Digest()},
			Signature:     sc.Signature(),
		}},
	}
	if !o.NoTlog {
		entries, err := e.TlogEntries()
		if err != nil {
			f.t.Fatal(err)
		}
		for _, en := range entries {
			b.VerificationMaterial.TlogEntries = append(b.VerificationMaterial.TlogEntries, f.fullEntry(en.TransparencyLogEntry()))
		}
	}
	out, err := protojson.Marshal(b)
	if err != nil {
		f.t.Fatal(err)
	}
	return out
}

// fullEntry completes the log entry of the virtual Sigstore the way Rekor answers: the entry's kind and version, the
// signed entry timestamp (inclusion promise) and the inclusion proof with its checkpoint.
func (f *Fake) fullEntry(tle *protorekor.TransparencyLogEntry) *protorekor.TransparencyLogEntry {
	f.t.Helper()
	logID, err := f.vs.RekorLogID()
	if err != nil {
		f.t.Fatal(err)
	}
	set, err := f.vs.RekorSignPayload(tlog.RekorPayload{
		Body: base64.StdEncoding.EncodeToString(tle.CanonicalizedBody), IntegratedTime: tle.IntegratedTime, LogIndex: tle.LogIndex, LogID: logID})
	if err != nil {
		f.t.Fatal(err)
	}
	proof, err := f.vs.GetInclusionProof(tle.CanonicalizedBody)
	if err != nil {
		f.t.Fatal(err)
	}
	root, err := hex.DecodeString(*proof.RootHash)
	if err != nil {
		f.t.Fatal(err)
	}
	tle.KindVersion = &protorekor.KindVersion{Kind: hashedrekord.KIND, Version: hashedrekord.New().DefaultVersion()}
	tle.InclusionPromise = &protorekor.InclusionPromise{SignedEntryTimestamp: set}
	tle.InclusionProof = &protorekor.InclusionProof{LogIndex: *proof.LogIndex, RootHash: root, TreeSize: *proof.TreeSize,
		Checkpoint: &protorekor.Checkpoint{Envelope: *proof.Checkpoint}}
	return tle
}
