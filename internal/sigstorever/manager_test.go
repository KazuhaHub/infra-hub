package sigstorever

import (
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/examples/repository/repository"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"golang.org/x/crypto/ed25519"
)

// testRepo is a small TUF repository served in memory (the shape of the one in sigstore-go's own tests).
type testRepo struct {
	t     *testing.T
	keys  map[string]ed25519.PrivateKey
	roles *repository.Type
	dir   string
	calls atomic.Int64
	down  atomic.Bool
}

func newTestRepo(t *testing.T) *testRepo {
	t.Helper()
	r := &testRepo{t: t, keys: map[string]ed25519.PrivateKey{}, roles: repository.New(), dir: t.TempDir()}
	tomorrow := time.Now().AddDate(0, 0, 1).UTC()
	r.roles.SetTargets(metadata.TARGETS, metadata.Targets(tomorrow))
	r.roles.SetSnapshot(metadata.Snapshot(tomorrow))
	r.roles.SetTimestamp(metadata.Timestamp(tomorrow))
	r.roles.SetRoot(metadata.Root(tomorrow))
	if err := os.Mkdir(filepath.Join(r.dir, metadata.TARGETS), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{metadata.TARGETS, metadata.SNAPSHOT, metadata.TIMESTAMP, metadata.ROOT} {
		_, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		r.keys[name] = priv
		key, err := metadata.KeyFromPublicKey(priv.Public())
		if err != nil {
			t.Fatal(err)
		}
		if err := r.roles.Root().Signed.AddKey(key, name); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range metadata.TOP_LEVEL_ROLE_NAMES {
		signer, err := signature.LoadSigner(r.keys[name], crypto.Hash(0))
		if err != nil {
			t.Fatal(err)
		}
		switch name {
		case metadata.TARGETS:
			_, err = r.roles.Targets(metadata.TARGETS).Sign(signer)
		case metadata.SNAPSHOT:
			_, err = r.roles.Snapshot().Sign(signer)
		case metadata.TIMESTAMP:
			_, err = r.roles.Timestamp().Sign(signer)
		case metadata.ROOT:
			_, err = r.roles.Root().Sign(signer)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func (r *testRepo) anchor() []byte {
	b, err := r.roles.Root().ToBytes(false)
	if err != nil {
		r.t.Fatal(err)
	}
	return b
}

func (r *testRepo) DownloadFile(urlPath string, _ int64, _ time.Duration) ([]byte, error) {
	r.calls.Add(1)
	if r.down.Load() {
		return nil, errors.New("network is down")
	}
	u, err := url.Parse(urlPath)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(u.Path, "/targets/") {
		m := regexp.MustCompile(`/targets/[0-9a-f]{64}\.(.*)$`).FindStringSubmatch(u.Path)
		if len(m) != 2 {
			return nil, &metadata.ErrDownloadHTTP{StatusCode: 404}
		}
		tf, ok := r.roles.Targets(metadata.TARGETS).Signed.Targets[m[1]]
		if !ok {
			return nil, &metadata.ErrDownloadHTTP{StatusCode: 404}
		}
		data, err := os.ReadFile(tf.Path)
		if err != nil {
			return nil, &metadata.ErrDownloadHTTP{StatusCode: 404}
		}
		return data, nil
	}
	if u.Path == "/timestamp.json" {
		return r.roles.Timestamp().ToBytes(false)
	}
	m := regexp.MustCompile(`/(\d+)\.(root|snapshot|targets)\.json$`).FindStringSubmatch(u.Path)
	if len(m) != 3 {
		return nil, &metadata.ErrDownloadHTTP{StatusCode: 404}
	}
	version, _ := strconv.Atoi(m[1])
	switch m[2] {
	case metadata.ROOT:
		if r.roles.Root().Signed.Version != int64(version) {
			return nil, &metadata.ErrDownloadHTTP{StatusCode: 404}
		}
		return r.roles.Root().ToBytes(false)
	case metadata.SNAPSHOT:
		if r.roles.Snapshot().Signed.Version != int64(version) {
			return nil, &metadata.ErrDownloadHTTP{StatusCode: 404}
		}
		return r.roles.Snapshot().ToBytes(false)
	default:
		if r.roles.Targets(metadata.TARGETS).Signed.Version != int64(version) {
			return nil, &metadata.ErrDownloadHTTP{StatusCode: 404}
		}
		return r.roles.Targets(metadata.TARGETS).ToBytes(false)
	}
}

func (r *testRepo) addTarget(name string, content []byte) {
	sum := sha256.Sum256(content)
	p := filepath.Join(r.dir, metadata.TARGETS, fmt.Sprintf("%x.%s", sum, name))
	if err := os.WriteFile(p, content, 0o600); err != nil {
		r.t.Fatal(err)
	}
	tf, err := metadata.TargetFile().FromFile(p, "sha256")
	if err != nil {
		r.t.Fatal(err)
	}
	tg := r.roles.Targets(metadata.TARGETS)
	tg.Signed.Targets[name] = tf
	tg.Signed.Version++
	r.roles.Snapshot().Signed.Meta["targets.json"] = metadata.MetaFile(tg.Signed.Version)
	r.roles.Snapshot().Signed.Version++
	r.roles.Timestamp().Signed.Meta["snapshot.json"] = metadata.MetaFile(r.roles.Snapshot().Signed.Version)
	r.roles.Timestamp().Signed.Version++
	for _, n := range []string{metadata.TARGETS, metadata.SNAPSHOT, metadata.TIMESTAMP} {
		signer, err := signature.LoadSigner(r.keys[n], crypto.Hash(0))
		if err != nil {
			r.t.Fatal(err)
		}
		switch n {
		case metadata.TARGETS:
			tg.ClearSignatures()
			_, err = tg.Sign(signer)
		case metadata.SNAPSHOT:
			r.roles.Snapshot().ClearSignatures()
			_, err = r.roles.Snapshot().Sign(signer)
		case metadata.TIMESTAMP:
			r.roles.Timestamp().ClearSignatures()
			_, err = r.roles.Timestamp().Sign(signer)
		}
		if err != nil {
			r.t.Fatal(err)
		}
	}
}

func newManager(t *testing.T, r *testRepo, anchor []byte, dir string) *Manager {
	t.Helper()
	if dir == "" {
		dir = filepath.Join(t.TempDir(), "tuf")
	}
	return &Manager{Dir: dir, InfoPath: filepath.Join(filepath.Dir(dir), "info.json"), BaseURL: "https://tuf.test", Anchor: anchor, Fetcher: r}
}

func TestManagerRefreshesThroughTUF(t *testing.T) {
	r := newTestRepo(t)
	r.addTarget("trusted_root.json", embeddedRoot)
	m := newManager(t, r, r.anchor(), "")
	tr, info, err := m.Root(context.Background())
	if err != nil || tr == nil || info.Source != SourceTUF || info.Updated.IsZero() {
		t.Fatalf("%v %+v", err, info)
	}
	if got, err := ReadInfo(m.InfoPath); err != nil || got.Source != SourceTUF {
		t.Errorf("info file %+v %v", got, err)
	}
	// Within a day the repository is not asked again.
	n := r.calls.Load()
	if _, info, _ := m.Root(context.Background()); info.Source != SourceTUF || r.calls.Load() != n {
		t.Errorf("asked again: %d calls", r.calls.Load()-n)
	}
	// A new process with the cache still fresh needs no network either.
	r.down.Store(true)
	m2 := newManager(t, r, r.anchor(), m.Dir)
	if _, info, err := m2.Root(context.Background()); err != nil || info.Source != SourceTUF {
		t.Errorf("fresh cache: %v %+v", err, info)
	}
}

func TestManagerKeepsTheCacheWhenTheNetworkFails(t *testing.T) {
	r := newTestRepo(t)
	r.addTarget("trusted_root.json", embeddedRoot)
	m := newManager(t, r, r.anchor(), "")
	if _, info, err := m.Root(context.Background()); err != nil || info.Source != SourceTUF {
		t.Fatalf("%v %+v", err, info)
	}
	// Make the cache three days old and take the network away.
	cfgPath := filepath.Join(m.Dir, tuf.URLToPath(m.BaseURL)+".json")
	if err := (&tuf.Config{LastTimestamp: time.Now().AddDate(0, 0, -3)}).Persist(cfgPath); err != nil {
		t.Fatal(err)
	}
	r.down.Store(true)
	m2 := newManager(t, r, r.anchor(), m.Dir)
	tr, info, err := m2.Root(context.Background())
	if err != nil || tr == nil || info.Source != SourceTUFCache || time.Since(info.Updated) < 48*time.Hour {
		t.Fatalf("%v %+v", err, info)
	}
	// A failed refresh is not retried at once.
	n := r.calls.Load()
	m2.Root(context.Background())
	if r.calls.Load() != n {
		t.Errorf("retried within the hour")
	}
}

func TestManagerFallsBackToTheEmbeddedRoot(t *testing.T) {
	r := newTestRepo(t)
	r.addTarget("trusted_root.json", embeddedRoot)
	r.down.Store(true)
	m := newManager(t, r, r.anchor(), "")
	tr, info, err := m.Root(context.Background())
	if err != nil || tr == nil || info.Source != SourceEmbedded || !info.Updated.IsZero() {
		t.Fatalf("%v %+v", err, info)
	}
}

// Metadata that does not verify under the TUF root the agent trusts is never used, whatever it says.
func TestManagerIgnoresARepositoryTheAnchorDoesNotTrust(t *testing.T) {
	evil := newTestRepo(t)
	evil.addTarget("trusted_root.json", []byte(`{"mediaType":"evil"}`))
	good := newTestRepo(t)
	m := newManager(t, evil, good.anchor(), "")
	_, info, err := m.Root(context.Background())
	if err != nil || info.Source != SourceEmbedded {
		t.Fatalf("%v %+v", err, info)
	}
	// And a target that is not a trusted root is not accepted either.
	bad := newTestRepo(t)
	bad.addTarget("trusted_root.json", []byte(`{"mediaType":"evil"}`))
	m = newManager(t, bad, bad.anchor(), "")
	if _, info, err := m.Root(context.Background()); err != nil || info.Source != SourceEmbedded {
		t.Fatalf("%v %+v", err, info)
	}
}

func TestManagerReportsTheEmbeddedFallbackAfterACacheExisted(t *testing.T) {
	r := newTestRepo(t)
	r.addTarget("trusted_root.json", embeddedRoot)
	m := newManager(t, r, r.anchor(), "")
	if _, info, err := m.Root(context.Background()); err != nil || info.Source != SourceTUF || info.Fallback {
		t.Fatalf("%v %+v", err, info)
	}
	// The cache becomes unreadable and the network is gone: the embedded root, flagged as a fallback.
	if err := os.RemoveAll(filepath.Join(m.Dir, tuf.URLToPath(m.BaseURL))); err != nil {
		t.Fatal(err)
	}
	r.down.Store(true)
	m2 := newManager(t, r, r.anchor(), m.Dir)
	_, info, err := m2.Root(context.Background())
	if err != nil || info.Source != SourceEmbedded || !info.Fallback || info.Since.IsZero() {
		t.Fatalf("%v %+v", err, info)
	}
	if got := InfoText(info); !strings.Contains(got, "embedded fallback (TUF unreachable since ") {
		t.Errorf("text %q", got)
	}
	if got, _ := ReadInfo(m2.InfoPath); !got.Fallback {
		t.Errorf("info file %+v", got)
	}
}

// A refresh that outlived its timeout may still be writing the cache: nothing reads or refreshes it until it has ended.
func TestManagerLeavesTheCacheAloneWhileARefreshIsRunning(t *testing.T) {
	r := newTestRepo(t)
	r.addTarget("trusted_root.json", embeddedRoot)
	m := newManager(t, r, r.anchor(), "")
	running := make(chan struct{})
	m.inflight = running
	before := r.calls.Load()
	if _, _, err := m.Root(context.Background()); err == nil {
		t.Fatal("a root without a running refresh to wait for")
	}
	if r.calls.Load() != before {
		t.Error("the repository was asked while a refresh was running")
	}
	close(running)
	if _, info, err := m.Root(context.Background()); err != nil || info.Source != SourceTUF {
		t.Fatalf("%v %+v", err, info)
	}
}
