package sigstorever

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"

	"github.com/KazuhaHub/infra-hub/internal/atomicfile"
)

// Where the trusted root came from.
const (
	// SourceEmbedded is the root built into the binary: no TUF metadata could be loaded.
	SourceEmbedded = "embedded"
	// SourceTUF is a root that TUF verified in this process's last refresh.
	SourceTUF = "tuf"
	// SourceTUFCache is a root from the TUF cache on disk, verified by an earlier refresh, used because the refresh
	// failed (no network, say).
	SourceTUFCache = "tuf-cache"
)

// Timing of the refresh.
const (
	// RefreshEvery is how often the TUF repository is asked for new metadata.
	RefreshEvery = 24 * time.Hour
	// RetryAfter is the wait after a failed refresh.
	RetryAfter = time.Hour
	// FetchTimeout bounds one refresh.
	FetchTimeout = 60 * time.Second
	targetName   = "trusted_root.json"
)

// Info says which trusted root is in use and how old it is; the manager writes it to a small file that
// `infra-agent status` reads.
type Info struct {
	Source string `json:"source"`
	// Updated is when TUF last refreshed the metadata that the root came from (zero for the embedded root).
	Updated time.Time `json:"updated,omitempty"`
	// Checked is when the manager last chose the root.
	Checked time.Time `json:"checked"`
	// Fallback is set when the embedded root is used although a TUF cache existed: TUF could not be reached or its cache
	// could not be read. Since is when TUF last refreshed (the cache's age).
	Fallback bool      `json:"fallback,omitempty"`
	Since    time.Time `json:"since,omitempty"`
}

// ReadInfo reads the file the manager wrote (an error when there is none).
func ReadInfo(path string) (Info, error) {
	var i Info
	data, err := os.ReadFile(path)
	if err != nil {
		return i, err
	}
	return i, json.Unmarshal(data, &i)
}

// Manager keeps the public-good trusted root current through TUF: the chain of trust is TUF's own (the embedded
// root.json of sigstore-go is the anchor, and new metadata must verify under it). The metadata is cached in Dir; the
// repository is asked at most every RefreshEvery, and when it cannot be reached the cached root, or at last the embedded
// one, is used.
type Manager struct {
	// Dir is the TUF cache directory; InfoPath the file for Info ("" for none).
	Dir, InfoPath string
	// BaseURL, Anchor and Fetcher override the public-good repository, its trust anchor and the HTTP fetcher (tests).
	BaseURL string
	Anchor  []byte
	Fetcher fetcher.Fetcher
	Now     func() time.Time
	// Offline never asks TUF and uses the embedded root (tests, and hosts that must not reach the network).
	Offline bool

	mu     sync.Mutex
	cur    *root.TrustedRoot
	info   Info
	nextAt time.Time // no refresh before this
	// inflight is closed when the last online attempt, which may outlive its timeout, has ended; the cache directory is
	// not touched (read or refreshed) before that.
	inflight <-chan struct{}
}

// NewManager is a manager for the public-good repository.
func NewManager(dir, infoPath string) *Manager { return &Manager{Dir: dir, InfoPath: infoPath} }

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Root returns the trusted root to verify with and where it came from. It never fails: the embedded root is the last
// resort (an error only if that does not parse).
func (m *Manager) Root(ctx context.Context) (*root.TrustedRoot, Info, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if m.cur != nil && now.Before(m.nextAt) {
		return m.cur, m.info, nil
	}
	tr, info, err := m.refresh(ctx)
	if err == nil {
		m.cur, m.info = tr, info
		m.nextAt = now.Add(RefreshEvery)
		if info.Source != SourceTUF {
			m.nextAt = now.Add(RetryAfter)
		}
		m.writeInfo()
		return tr, info, nil
	}
	if m.cur != nil { // keep what worked before
		m.nextAt = now.Add(RetryAfter)
		return m.cur, m.info, nil
	}
	return nil, Info{}, err
}

func (m *Manager) writeInfo() {
	if m.InfoPath == "" {
		return
	}
	if data, err := json.Marshal(m.info); err == nil {
		_ = os.MkdirAll(filepath.Dir(m.InfoPath), 0o700)
		_ = atomicfile.Write(m.InfoPath, append(data, '\n'), 0o600)
	}
}

func (m *Manager) options() *tuf.Options {
	o := tuf.DefaultOptions().WithCachePath(m.Dir).WithCacheValidity(1)
	if m.BaseURL != "" {
		o.WithRepositoryBaseURL(m.BaseURL)
	}
	if m.Anchor != nil {
		o.WithRoot(m.Anchor)
	}
	if m.Fetcher != nil {
		o.WithFetcher(m.Fetcher)
	}
	return o
}

func (m *Manager) refresh(ctx context.Context) (*root.TrustedRoot, Info, error) {
	now := m.now()
	cached := false
	if !m.Offline && m.busy() {
		// An earlier attempt is still running in the background: leave the cache alone this time.
		return nil, Info{}, errors.New("an earlier TUF refresh is still running")
	}
	if !m.Offline {
		if err := os.MkdirAll(m.Dir, 0o700); err == nil {
			cached = !m.lastUpdate().IsZero()
			// A fresh cache (younger than a day) is used without the network; an older one is refreshed.
			data, timedOut, err := m.fromTUF(ctx, m.options())
			if err == nil {
				if tr, err := root.NewTrustedRootFromJSON(data); err == nil {
					return tr, Info{Source: SourceTUF, Updated: m.lastUpdate(), Checked: now}, nil
				}
			}
			if !timedOut {
				// No network or a bad answer: the cache as it is.
				if data, _, err := m.fromTUF(ctx, m.options().WithForceCache()); err == nil {
					if tr, err := root.NewTrustedRootFromJSON(data); err == nil {
						return tr, Info{Source: SourceTUFCache, Updated: m.lastUpdate(), Checked: now}, nil
					}
				}
			}
		}
	}
	tr, err := EmbeddedRoot()
	if err != nil {
		return nil, Info{}, err
	}
	info := Info{Source: SourceEmbedded, Checked: now}
	if cached {
		info.Fallback, info.Since = true, m.lastUpdate()
	}
	return tr, info, nil
}

func (m *Manager) busy() bool {
	if m.inflight == nil {
		return false
	}
	select {
	case <-m.inflight:
		return false
	default:
		return true
	}
}

// lastUpdate is when TUF last refreshed the cache (the library's own record; zero if unknown).
func (m *Manager) lastUpdate() time.Time {
	base := m.BaseURL
	if base == "" {
		base = tuf.DefaultMirror
	}
	cfg, err := tuf.LoadConfig(filepath.Join(m.Dir, fmt.Sprintf("%s.json", tuf.URLToPath(base))))
	if err != nil {
		return time.Time{}
	}
	return cfg.LastTimestamp
}

// fromTUF reads the trusted root target through a TUF client, within FetchTimeout and ctx. When the time is up the
// attempt is cancelled but may still be running: timedOut is true, and m.inflight says when it has ended, so that
// nothing else reads or writes the cache meanwhile.
func (m *Manager) fromTUF(ctx context.Context, o *tuf.Options) (data []byte, timedOut bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, FetchTimeout)
	defer cancel()
	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := tuf.New(o.WithContext(ctx))
		if err != nil {
			ch <- result{nil, err}
			return
		}
		data, err := c.GetTarget(targetName)
		ch <- result{data, err}
	}()
	select {
	case r := <-ch:
		<-done
		return r.data, false, r.err
	case <-ctx.Done():
		m.inflight = done
		return nil, true, errors.New("the TUF refresh did not finish in time")
	}
}

// InfoText says where the trusted root came from and how old that is.
func InfoText(i Info) string {
	switch {
	case i.Fallback:
		return fmt.Sprintf("embedded fallback (TUF unreachable since %s)", i.Since.UTC().Format(time.RFC3339))
	case i.Updated.IsZero():
		return i.Source
	}
	return fmt.Sprintf("%s, TUF metadata refreshed %s (%s ago)", i.Source, i.Updated.UTC().Format(time.RFC3339), time.Since(i.Updated).Round(time.Minute))
}
