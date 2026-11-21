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

// Bundles serves GET /v1/bundle/<host>: the files of the config bundle, read from the mirror's main-attestation
// branch and age-encrypted to the host. By default the archive is format 1 (bundle, bundle.sig, bundle.tar.gz), a
// request with X-Infra-Bundle-Format: 2 adds bundle.sigstore.json, and format 3 (agents of v0.15.0 and later) is
// bundle, bundle.tar.gz and bundle.sigstore.json. Formats 1 and 2 need the legacy bundle.sig on the branch; without it
// they are answered with 406 format_unavailable. The hub does not verify the signature or the hash; the agent does.
//
// Only the current tip of main-attestation is ever held. Per tip the hub keeps the parsed statement (so an unchanged
// poll is a 304 without reading the tarball), the plain ustar archive (built once and shared by all hosts), and the
// ciphertext per host. A new tip drops all of it.
type Bundles struct {
	Repo string
	// Fresh returns an error when the mirror is too old to serve from.
	Fresh func() error
	// Limits defaults to bundle.DefaultLimits.
	Limits bundle.Limits

	mu     sync.Mutex // also serializes git reads: the tip is read under it, so no request works from an older tip
	cur    *tipState
	builds int // archives built (tests)

	wmu  sync.Mutex // guards wake
	wake chan struct{}
}

type tipState struct {
	tip      string
	stmt     *bundle.Statement
	archives map[int][]byte    // plain ustar by format, built on the first full request
	enc      map[string][]byte // ciphertext by host and format (encKey)
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

// tipLocked reads the tip of main-attestation and makes sure the cache describes it, with its statement parsed. The
// caller holds b.mu.
func (b *Bundles) tipLocked(ctx context.Context) (*tipState, error) {
	tip, err := bundle.Tip(ctx, b.Repo)
	if err != nil {
		b.cur = nil
		return nil, err
	}
	if b.cur == nil || b.cur.tip != tip {
		b.cur = &tipState{tip: tip, enc: map[string][]byte{}}
	}
	c := b.cur
	if c.stmt == nil {
		st, err := bundle.Inspect(ctx, b.Repo, tip, b.limits())
		if err != nil {
			return nil, err
		}
		c.stmt = &st
	}
	return c, nil
}

// Commit returns the commit of the bundle the hub would serve now (the ETag without the quotes).
func (b *Bundles) Commit(ctx context.Context) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	c, err := b.tipLocked(ctx)
	if err != nil {
		return "", err
	}
	return c.stmt.Commit, nil
}

// Poke wakes everything that waits for the bundle to change; the mirror calls it after every successful fetch.
func (b *Bundles) Poke() {
	b.wmu.Lock()
	defer b.wmu.Unlock()
	if b.wake != nil {
		close(b.wake)
	}
	b.wake = nil
}

// wakeChan returns a channel that is closed by the next Poke.
func (b *Bundles) wakeChan() <-chan struct{} {
	b.wmu.Lock()
	defer b.wmu.Unlock()
	if b.wake == nil {
		b.wake = make(chan struct{})
	}
	return b.wake
}

// serve returns the commit of the current bundle and, unless ifNoneMatch names it, the ciphertext for host.
func (b *Bundles) serve(ctx context.Context, host string, rcpt age.Recipient, ifNoneMatch string, format int) (commit string, body []byte, notModified bool, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	c, err := b.tipLocked(ctx)
	if err != nil {
		return "", nil, false, err
	}
	tip := c.tip
	commit = c.stmt.Commit
	if ifNoneMatch != "" && etagMatches(ifNoneMatch, etagOf(commit)) {
		return commit, nil, true, nil
	}
	key := encKey(host, format)
	if ct, ok := c.enc[key]; ok {
		return commit, ct, false, nil
	}
	archive := c.archives[format]
	if archive == nil {
		l, err := bundle.LoadAt(ctx, b.Repo, tip, b.limits())
		if err != nil {
			return "", nil, false, err
		}
		if l.Statement != *c.stmt {
			return "", nil, false, fmt.Errorf("%w: the statement changed while it was read", bundle.ErrNoBundle)
		}
		if archive, err = bundle.Archive(l.Files, time.Unix(l.Statement.Time, 0), format); err != nil {
			return "", nil, false, err
		}
		if c.archives == nil {
			c.archives = map[int][]byte{}
		}
		c.archives[format] = archive
		b.builds++
	}
	var buf bytes.Buffer
	buf.Grow(len(archive) + 1<<10)
	w, err := age.Encrypt(&buf, rcpt)
	if err != nil {
		return "", nil, false, err
	}
	if _, err := w.Write(archive); err != nil {
		return "", nil, false, err
	}
	if err := w.Close(); err != nil {
		return "", nil, false, err
	}
	ct := buf.Bytes()
	total := len(ct)
	for _, a := range c.archives {
		total += len(a)
	}
	for k, o := range c.enc {
		if total+len(o) > maxCacheBytes {
			delete(c.enc, k)
			continue
		}
		total += len(o)
	}
	if total <= maxCacheBytes {
		c.enc[key] = ct
	}
	return commit, ct, false, nil
}

// encKey is the key of a host's ciphertext: it differs by format.
func encKey(host string, format int) string { return host + "\x00" + strconv.Itoa(format) }

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

// FormatHeader is the request header with which a client asks for an archive format (docs/bundle.md). Without it the
// answer is format 1. A number above 3 is answered as format 3, the highest this hub knows.
const FormatHeader = "X-Infra-Bundle-Format"

// requestedFormat reads FormatHeader.
func requestedFormat(r *http.Request) (int, bool) {
	v := r.Header.Get(FormatHeader)
	if v == "" {
		return bundle.Format1, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || len(v) > 3 {
		return 0, false
	}
	return min(n, bundle.Format3), true
}

func (s *Server) bundle(w http.ResponseWriter, r *http.Request, host string) {
	w.Header().Add("Vary", FormatHeader)
	if !s.bundleIP.allow(remoteKey(r.RemoteAddr), s.Now()) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests from this address")
		return
	}
	format, ok := requestedFormat(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_format", FormatHeader+" must be a positive number")
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
	commit, body, notModified, err := s.Bundles.serve(r.Context(), host, rcpt, r.Header.Get("If-None-Match"), format)
	if err != nil {
		if errors.Is(err, bundle.ErrFormatUnavailable) {
			slog.Warn("archive format not available", "host", host, "format", format, "err", err)
			writeError(w, http.StatusNotAcceptable, "format_unavailable", "this archive format needs bundle.sig, which the hub's bundle no longer has: update infra-agent")
		} else if errors.Is(err, bundle.ErrNoBundle) {
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
