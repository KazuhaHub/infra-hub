package httpsapi

import (
	"log/slog"
	"net/http"
	"regexp"
	"sync"
	"time"
)

// Defaults and limits of GET /v1/wait/<host>.
const (
	// DefaultWaitTimeout is how long the hub holds a request when the bundle does not change. It stays below the idle
	// timeouts of the proxies and NATs between an agent and a hub (commonly 5 minutes).
	DefaultWaitTimeout = 4 * time.Minute
	// MaxWaitTimeout is the longest a hub may be configured to hold a request; agents give up after WaitClientTimeout.
	MaxWaitTimeout = 5 * time.Minute
	// DefaultWaitRecheck is how often a held request looks at the bundle on its own, in case a wake-up was missed.
	DefaultWaitRecheck = 30 * time.Second
	// MaxWaitersPerHost and MaxWaitersTotal cap the requests held at once.
	MaxWaitersPerHost = 2
	MaxWaitersTotal   = 256
)

var etagParam = regexp.MustCompile(`^([0-9a-f]{40}([0-9a-f]{24})?)?$`)

// waiters counts the held requests.
type waiters struct {
	mu      sync.Mutex
	perHost map[string]int
	total   int
}

func (w *waiters) acquire(host string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.perHost == nil {
		w.perHost = map[string]int{}
	}
	if w.total >= MaxWaitersTotal || w.perHost[host] >= MaxWaitersPerHost {
		return false
	}
	w.total++
	w.perHost[host]++
	return true
}

func (w *waiters) release(host string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.total--
	if w.perHost[host]--; w.perHost[host] <= 0 {
		delete(w.perHost, host)
	}
}

// count is the number of held requests (tests).
func (w *waiters) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.total
}

// wait answers GET /v1/wait/<host>?etag=<commit>: at once {"changed":true,"commit":...} when the bundle the hub would
// serve now is not the one named by etag, otherwise it holds the request until the mirror brings a different bundle or
// the timeout, and then answers {"changed":false}. The answer carries no secret: the commit is what the ETag of
// /v1/bundle/<host> shows anyway, and the bundle itself still has to be fetched, decrypted and verified by the agent.
func (s *Server) wait(w http.ResponseWriter, r *http.Request, host string) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		return
	}
	if !s.waitIP.allow(remoteKey(r.RemoteAddr), s.Now()) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests from this address")
		return
	}
	if _, known := s.Recipients[host]; !known {
		writeError(w, http.StatusNotFound, "unknown_host", "no such host")
		return
	}
	etag := r.URL.Query().Get("etag")
	if !etagParam.MatchString(etag) {
		writeError(w, http.StatusBadRequest, "bad_request", "etag must be a commit id")
		return
	}
	if s.Bundles == nil {
		writeError(w, http.StatusServiceUnavailable, "no_bundle", "this hub serves no bundles")
		return
	}
	if s.Bundles.Fresh != nil {
		if err := s.Bundles.Fresh(); err != nil {
			writeError(w, http.StatusServiceUnavailable, "stale_mirror", "the hub's mirror is out of date")
			return
		}
	}
	// The wake-up channel is taken before the first look, so a change in between is not missed.
	wake := s.Bundles.wakeChan()
	commit, err := s.Bundles.Commit(r.Context())
	if err != nil {
		slog.Warn("wait refused, no bundle", "host", host, "err", err)
		writeError(w, http.StatusServiceUnavailable, "no_bundle", "the hub has no valid bundle to serve")
		return
	}
	if commit != etag {
		writeChanged(w, commit)
		return
	}
	if !s.waits.acquire(host) {
		writeError(w, http.StatusTooManyRequests, "too_many_waiters", "too many waiting requests for this host")
		return
	}
	defer s.waits.release(host)
	// The server's read and write timeouts are far shorter than a hold; they are moved for this request only.
	timeout := s.WaitTimeout
	if timeout <= 0 {
		timeout = DefaultWaitTimeout
	}
	rc := http.NewResponseController(w)
	until := time.Now().Add(timeout + 15*time.Second)
	_ = rc.SetReadDeadline(until)
	_ = rc.SetWriteDeadline(until)
	recheck := s.WaitRecheck
	if recheck <= 0 {
		recheck = DefaultWaitRecheck
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(recheck)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done(): // the client went away, or the server is shutting down
			return
		case <-deadline.C:
			writeJSON(w, http.StatusOK, map[string]any{"apiVersion": APIVersion, "changed": false})
			return
		case <-wake:
			wake = s.Bundles.wakeChan()
		case <-tick.C:
		}
		// A bundle that cannot be read now (a broken tip) is not a change; the request keeps waiting.
		if c, err := s.Bundles.Commit(r.Context()); err == nil && c != etag {
			writeChanged(w, c)
			return
		}
	}
}

func writeChanged(w http.ResponseWriter, commit string) {
	writeJSON(w, http.StatusOK, map[string]any{"apiVersion": APIVersion, "changed": true, "commit": commit})
}
