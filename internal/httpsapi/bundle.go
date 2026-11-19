package httpsapi

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"filippo.io/age"

	"github.com/KazuhaHub/infra-hub/internal/bundle"
)

// maxCacheBytes bounds the encrypted bundles held in memory (one per host, the newest tip only).
const maxCacheBytes = 256 << 20

// Bundles serves GET /v1/bundle/<host>: the three files of the config bundle, read from the mirror's main-attestation
// branch and age-encrypted to the host. The hub does not verify the signature or the hash; the agent does.
type Bundles struct {
	Repo string
	// Fresh returns an error when the mirror is too old to serve from (the same rule as the SSH side).
	Fresh func() error
	// Limits defaults to bundle.DefaultLimits.
	Limits bundle.Limits

	mu    sync.Mutex
	cache map[string]cachedBundle // by host; only entries for the current tip survive
}

type cachedBundle struct {
	tip    string
	commit string
	body   []byte
}

func (b *Bundles) limits() bundle.Limits {
	if b.Limits == (bundle.Limits{}) {
		return bundle.DefaultLimits
	}
	return b.Limits
}

// current returns the encrypted bundle of host for the present tip. A tip that moved drops every older entry.
func (b *Bundles) current(r *http.Request, host string, rcpt age.Recipient) (commit string, body []byte, err error) {
	tip, err := bundle.Tip(r.Context(), b.Repo)
	if err != nil {
		return "", nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock() // loads are serialized: one read of a big bundle at a time
	for h, c := range b.cache {
		if c.tip != tip {
			delete(b.cache, h)
		}
	}
	if c, ok := b.cache[host]; ok {
		return c.commit, c.body, nil
	}
	l, err := bundle.LoadAt(r.Context(), b.Repo, tip, b.limits())
	if err != nil {
		return "", nil, err
	}
	tarball, err := bundle.Archive(l.Files, time.Unix(l.Statement.Time, 0))
	if err != nil {
		return "", nil, err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, rcpt)
	if err != nil {
		return "", nil, err
	}
	if _, err := w.Write(tarball); err != nil {
		return "", nil, err
	}
	if err := w.Close(); err != nil {
		return "", nil, err
	}
	c := cachedBundle{tip: tip, commit: l.Statement.Commit, body: buf.Bytes()}
	if b.cache == nil {
		b.cache = map[string]cachedBundle{}
	}
	total := len(c.body)
	for h, o := range b.cache {
		if total+len(o.body) > maxCacheBytes {
			delete(b.cache, h)
			continue
		}
		total += len(o.body)
	}
	if total <= maxCacheBytes {
		b.cache[host] = c
	}
	return c.commit, c.body, nil
}

// etagMatches reports whether an If-None-Match header names etag (weak validators and lists are understood).
func etagMatches(header, etag string) bool {
	for _, p := range strings.Split(header, ",") {
		p = strings.TrimPrefix(strings.TrimSpace(p), "W/")
		if p == "*" || p == etag {
			return true
		}
	}
	return false
}

func (s *Server) bundle(w http.ResponseWriter, r *http.Request, host string) {
	if !s.bundleIP.allow(remoteKey(r.RemoteAddr), s.Now()) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests from this address")
		return
	}
	rcpt, known := s.Recipients[host]
	if !known {
		writeError(w, http.StatusNotFound, "unknown_host", "no such host")
		return
	}
	if s.Bundles == nil {
		writeError(w, http.StatusServiceUnavailable, "no_bundle", "this hub serves no bundles")
		return
	}
	if s.Bundles.Fresh != nil {
		if err := s.Bundles.Fresh(); err != nil {
			slog.Warn("bundle refused, mirror is stale", "host", host, "err", err)
			writeError(w, http.StatusServiceUnavailable, "stale_mirror", "the hub's mirror is out of date")
			return
		}
	}
	commit, body, err := s.Bundles.current(r, host, rcpt)
	if err != nil {
		if errors.Is(err, bundle.ErrNoBundle) {
			slog.Warn("no bundle to serve", "host", host, "err", err)
			writeError(w, http.StatusServiceUnavailable, "no_bundle", "the hub has no valid bundle to serve")
		} else {
			slog.Error("cannot prepare the bundle", "host", host, "err", err)
			writeError(w, http.StatusInternalServerError, "internal", "cannot prepare the bundle")
		}
		return
	}
	etag := fmt.Sprintf("%q", commit)
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-store")
	if inm := r.Header.Get("If-None-Match"); inm != "" && etagMatches(inm, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}
