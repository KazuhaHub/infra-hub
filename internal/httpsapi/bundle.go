package httpsapi

import (
	"bytes"
	"context"
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

// maxCacheBytes bounds what is kept in memory for the current tip: the plain archive plus the encrypted copies.
const maxCacheBytes = 256 << 20

// Bundles serves GET /v1/bundle/<host>: the three files of the config bundle, read from the mirror's main-attestation
// branch and age-encrypted to the host. The hub does not verify the signature or the hash; the agent does.
//
// Only the current tip of main-attestation is ever held. Per tip the hub keeps the parsed statement (so an unchanged
// poll is a 304 without reading the tarball), the plain ustar archive (built once and shared by all hosts), and the
// ciphertext per host. A new tip drops all of it.
type Bundles struct {
	Repo string
	// Fresh returns an error when the mirror is too old to serve from (the same rule as the SSH side).
	Fresh func() error
	// Limits defaults to bundle.DefaultLimits.
	Limits bundle.Limits

	mu     sync.Mutex // also serializes git reads: the tip is read under it, so no request works from an older tip
	cur    *tipState
	builds int // archives built (tests)
}

type tipState struct {
	tip     string
	stmt    *bundle.Statement
	archive []byte            // plain ustar, built on the first full request
	enc     map[string][]byte // ciphertext by host
}

func (b *Bundles) limits() bundle.Limits {
	if b.Limits == (bundle.Limits{}) {
		return bundle.DefaultLimits
	}
	return b.Limits
}

func (b *Bundles) cachedEncrypted() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cur == nil {
		return 0
	}
	return len(b.cur.enc)
}

// serve returns the commit of the current bundle and, unless ifNoneMatch names it, the ciphertext for host.
func (b *Bundles) serve(ctx context.Context, host string, rcpt age.Recipient, ifNoneMatch string) (commit string, body []byte, notModified bool, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	tip, err := bundle.Tip(ctx, b.Repo)
	if err != nil {
		b.cur = nil
		return "", nil, false, err
	}
	if b.cur == nil || b.cur.tip != tip {
		b.cur = &tipState{tip: tip, enc: map[string][]byte{}}
	}
	c := b.cur
	if c.stmt == nil {
		st, err := bundle.Inspect(ctx, b.Repo, tip, b.limits())
		if err != nil {
			return "", nil, false, err
		}
		c.stmt = &st
	}
	commit = c.stmt.Commit
	if ifNoneMatch != "" && etagMatches(ifNoneMatch, etagOf(commit)) {
		return commit, nil, true, nil
	}
	if ct, ok := c.enc[host]; ok {
		return commit, ct, false, nil
	}
	if c.archive == nil {
		l, err := bundle.LoadAt(ctx, b.Repo, tip, b.limits())
		if err != nil {
			return "", nil, false, err
		}
		if l.Statement != *c.stmt {
			return "", nil, false, fmt.Errorf("%w: the statement changed while it was read", bundle.ErrNoBundle)
		}
		if c.archive, err = bundle.Archive(l.Files, time.Unix(l.Statement.Time, 0)); err != nil {
			return "", nil, false, err
		}
		b.builds++
	}
	var buf bytes.Buffer
	buf.Grow(len(c.archive) + 1<<10)
	w, err := age.Encrypt(&buf, rcpt)
	if err != nil {
		return "", nil, false, err
	}
	if _, err := w.Write(c.archive); err != nil {
		return "", nil, false, err
	}
	if err := w.Close(); err != nil {
		return "", nil, false, err
	}
	ct := buf.Bytes()
	total := len(c.archive) + len(ct)
	for h, o := range c.enc {
		if total+len(o) > maxCacheBytes {
			delete(c.enc, h)
			continue
		}
		total += len(o)
	}
	if total <= maxCacheBytes {
		c.enc[host] = ct
	}
	return commit, ct, false, nil
}

func etagOf(commit string) string { return `"` + commit + `"` }

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
	commit, body, notModified, err := s.Bundles.serve(r.Context(), host, rcpt, r.Header.Get("If-None-Match"))
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
	w.Header().Set("ETag", etagOf(commit))
	w.Header().Set("Cache-Control", "no-store")
	if notModified {
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
