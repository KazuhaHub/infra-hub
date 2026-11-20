package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

// Kick: instead of sleeping between cycles, the agent holds a long request (GET /v1/wait/<host>?etag=<commit>) open to
// the first hub that supports it. The hub answers when the bundle it would serve is not the verified one, or after its
// timeout. The agent still only connects outward, and the interval stays the upper bound between cycles: a hub without
// the endpoint (404) or a failing one changes nothing about that.
const (
	// WaitClientTimeout bounds one wait request; hubs hold for at most 5 minutes (httpsapi.MaxWaitTimeout).
	WaitClientTimeout = 5*time.Minute + 30*time.Second
	// DefaultMinCycleGap is the shortest time between the start of one cycle and the start of a cycle caused by a kick.
	DefaultMinCycleGap = 10 * time.Second
	// noKickFor is how long a hub that answered 404 is left alone.
	noKickFor = time.Hour
	// Backoff after a failed wait request.
	kickBackoffMin = 15 * time.Second
	kickBackoffMax = 5 * time.Minute
)

// errNoKick means the hub does not know /v1/wait.
var errNoKick = errors.New("the hub has no /v1/wait")

func (h *Hub) kickSuspended(now time.Time) bool {
	h.kickMu.Lock()
	defer h.kickMu.Unlock()
	return now.Before(h.noKickUntil)
}

func (h *Hub) suspendKick(until time.Time) {
	h.kickMu.Lock()
	h.noKickUntil = until
	h.kickMu.Unlock()
}

// Wait holds a request open until the hub's bundle is not the one named by etag (the commit last verified, "" for
// none) or the hub's timeout. changed is true with the new commit, or false when nothing changed. A 404 without the
// hub's own error code is errNoKick (an older hub).
func (h *Hub) Wait(ctx context.Context, host, etag string) (changed bool, commit string, err error) {
	q := url.Values{"etag": {etag}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.URL+"/v1/wait/"+url.PathEscape(host)+"?"+q.Encode(), nil)
	if err != nil {
		return false, "", err
	}
	req.Header.Set("User-Agent", "infra-agent")
	resp, err := h.waitClient.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSmall+1))
	if err != nil {
		return false, "", err
	}
	if len(data) > maxSmall {
		return false, "", errors.New("the wait answer is too large")
	}
	var doc struct {
		APIVersion string `json:"apiVersion"`
		Changed    *bool  `json:"changed"`
		Commit     string `json:"commit"`
		Error      struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(data, &doc)
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound && (doc.Error.Code == "" || doc.Error.Code == "not_found") {
			return false, "", errNoKick
		}
		return false, "", &HubError{Status: resp.StatusCode, Code: doc.Error.Code}
	}
	if doc.APIVersion != "v1" || doc.Changed == nil {
		return false, "", errors.New("the wait answer is not apiVersion v1 with a changed field")
	}
	if *doc.Changed && !commitHex.MatchString(doc.Commit) {
		return false, "", errors.New("the wait answer names no commit")
	}
	return *doc.Changed, doc.Commit, nil
}

// waitKick spends the time until `until` waiting for a kick, and returns true as soon as a hub says the bundle changed
// (commit is what it named). It returns false when the time is up, when no hub supports waiting, or when ctx ends. It
// never loops without sleeping: a failed or instant "unchanged" answer is followed by a pause. It uses the real clock
// (a.Now is for what is recorded, and tests move it).
func (a *Agent) waitKick(ctx context.Context, etag string, until time.Time) (bool, string) {
	backoff := kickBackoffMin
	for {
		now := time.Now()
		if !now.Before(until) || ctx.Err() != nil {
			return false, ""
		}
		var hub *Hub
		for _, h := range a.Hubs {
			if !h.kickSuspended(now) {
				hub = h
				break
			}
		}
		if hub == nil {
			pause(ctx, until, time.Until(until))
			return false, ""
		}
		wctx, cancel := context.WithDeadline(ctx, until)
		started := time.Now()
		changed, commit, err := hub.Wait(wctx, a.Cfg.Host, etag)
		cancel()
		switch {
		case ctx.Err() != nil:
			return false, ""
		case errors.Is(err, errNoKick):
			slog.Info("hub has no /v1/wait, not asking it again for a while", "hub", hub.URL)
			hub.suspendKick(time.Now().Add(noKickFor))
			continue
		case err != nil && !time.Now().Before(until): // our own deadline: the interval is over
			return false, ""
		case err != nil:
			slog.Warn("wait for a new bundle failed", "hub", hub.URL, "err", err)
			if !pause(ctx, until, Jitter(backoff)) {
				return false, ""
			}
			backoff = min(backoff*2, kickBackoffMax)
			continue
		case changed:
			return true, commit
		}
		backoff = kickBackoffMin
		// "No change". A hub that answers this at once would be asked again at once: keep a gap.
		if took := time.Since(started); took < a.minGap() {
			if !pause(ctx, until, a.minGap()-took) {
				return false, ""
			}
		}
	}
}

func (a *Agent) minGap() time.Duration {
	if a.MinCycleGap > 0 {
		return a.MinCycleGap
	}
	return DefaultMinCycleGap
}

// pause sleeps d, or until `until` or ctx ends; it reports whether time is left after it.
func pause(ctx context.Context, until time.Time, d time.Duration) bool {
	if rest := time.Until(until); d > rest {
		d = rest
	}
	if d > 0 {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(d):
		}
	}
	return ctx.Err() == nil && time.Now().Before(until)
}
