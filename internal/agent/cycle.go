package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"os"
	"time"
	"unicode/utf8"

	"github.com/KazuhaHub/infra-hub/internal/bundle"
)

// Results of a cycle (and of its report).
const (
	ResultOK          = "ok"          // applied
	ResultVerified    = "verified"    // fetched and verified, nothing applied (verify mode)
	ResultUnchanged   = "unchanged"   // nothing new
	ResultFailed      = "failed"      // ansible failed
	ResultRejected    = "rejected"    // a signature, hash or format check failed
	ResultUnreachable = "unreachable" // no hub gave a bundle
)

// ReapplyAfter is how long a successful apply stays current: after it the same commit is applied again (as
// infra-pull does), which repairs drift.
const ReapplyAfter = 24 * time.Hour

// MaxMessage is the longest message of a report.
const MaxMessage = 500

// Agent runs cycles for one host.
type Agent struct {
	Cfg  Config
	ID   *Identity
	Hubs []*Hub

	// SSHKeygen and Ansible are the programs to run (defaults ssh-keygen and ansible-playbook, found through PATH).
	SSHKeygen, Ansible string
	// Out receives ansible's output (default os.Stderr, which is the journal under systemd).
	Out io.Writer
	Now func() time.Time
}

// New builds an agent from a validated configuration and its age identity.
func New(cfg Config, id *Identity) (*Agent, error) {
	a := &Agent{Cfg: cfg, ID: id, SSHKeygen: "ssh-keygen", Ansible: "ansible-playbook", Out: os.Stderr, Now: time.Now}
	for _, u := range cfg.Token.Hubs {
		h, err := NewHub(u, cfg.Token.Pins)
		if err != nil {
			return nil, err
		}
		a.Hubs = append(a.Hubs, h)
	}
	return a, nil
}

// Outcome is the result of one cycle.
type Outcome struct {
	Result        string
	Message       string
	AppliedCommit string // the commit ansible last applied successfully ("" if none)
	Hub           string // the hub that served the bundle ("" if none did)
	Reported      bool
}

// Cycle runs one fetch, verify, extract, apply and report. The error is for faults of the agent itself (the state
// cannot be read or written); every outcome that is about the bundle or the hubs is a Result instead.
func (a *Agent) Cycle(ctx context.Context) (Outcome, error) {
	if err := PrepareDir(a.Cfg.StateDir); err != nil {
		return Outcome{}, err
	}
	st, err := LoadState(a.Cfg.StateDir)
	if err != nil {
		return Outcome{}, err
	}
	started := a.Now()
	o, served := a.fetchAndApply(ctx, &st)
	if st.Applied != nil {
		o.AppliedCommit = st.Applied.Commit
	}
	o.Message = truncate(o.Message, MaxMessage)
	st.LastResult, st.LastMessage, st.LastHub = o.Result, o.Message, o.Hub
	at := a.now()
	st.LastCycle = &at
	if err := st.Save(a.Cfg.StateDir); err != nil {
		return o, fmt.Errorf("write state: %w", err)
	}
	var protect []string
	if st.Verified != nil {
		protect = append(protect, st.Verified.Commit)
	}
	if st.Applied != nil {
		protect = append(protect, st.Applied.Commit)
	}
	if err := PruneReleases(a.Cfg.StateDir, KeepReleases, protect...); err != nil {
		slog.Warn("cannot prune old releases", "err", err)
	}
	slog.Info("cycle finished", "host", a.Cfg.Host, "result", o.Result, "hub", o.Hub, "took", a.Now().Sub(started).Round(time.Millisecond), "message", o.Message)
	if ctx.Err() == nil {
		o.Reported = a.report(ctx, served, o)
	}
	return o, nil
}

// fetchAndApply does the work of a cycle and updates st (it does not save the cycle's own fields).
func (a *Agent) fetchAndApply(ctx context.Context, st *State) (Outcome, *Hub) {
	cfg := a.Cfg
	// A 304 only means something while the release it refers to is still on disk.
	etag := ""
	if st.Verified != nil {
		if _, err := os.Stat(ReleaseDir(cfg.StateDir, st.Verified.Commit)); err == nil {
			etag = st.Verified.Commit
		}
	}
	var (
		served     *Hub
		target     string // the commit to apply, if any
		newBundle  bool
		rejected   error
		rejectedAt *Hub
		hubErrs    int
	)
hubs:
	for _, hub := range a.Hubs {
		if ctx.Err() != nil {
			break
		}
		body, notModified, err := hub.Bundle(ctx, cfg.Host, etag)
		if err != nil {
			hubErrs++
			slog.Warn("hub did not give a bundle, trying the next", "hub", hub.URL, "err", err)
			continue
		}
		if notModified {
			served = hub
			if st.Verified != nil {
				target = st.Verified.Commit
			}
			slog.Debug("bundle unchanged", "hub", hub.URL)
			break hubs
		}
		stmt, status, err := a.accept(ctx, st, body)
		var rj *RejectError
		switch {
		case errors.As(err, &rj):
			rejected, rejectedAt = err, hub
			slog.Warn("bundle rejected, trying the next hub", "hub", hub.URL, "err", err)
			continue
		case err != nil:
			return Outcome{Result: ResultFailed, Message: "cannot process the bundle: " + err.Error(), Hub: hub.URL}, hub
		}
		served = hub
		switch status {
		case statusNew:
			newBundle, target = true, stmt.Commit
		case statusSame:
			target = stmt.Commit
		default: // older: keep working on what is already verified
			if st.Verified != nil {
				target = st.Verified.Commit
			}
		}
		break hubs
	}
	if served == nil {
		if rejected != nil {
			return Outcome{Result: ResultRejected, Message: "bundle rejected: " + rejected.Error(), Hub: rejectedAt.URL}, rejectedAt
		}
		return Outcome{Result: ResultUnreachable, Message: fmt.Sprintf("no hub gave a bundle (%d of %d tried)", hubErrs, len(a.Hubs))}, nil
	}
	o := Outcome{Hub: served.URL}
	if cfg.Mode == ModeVerify {
		if newBundle {
			o.Result, o.Message = ResultVerified, fmt.Sprintf("verified %s; verify mode, nothing applied", short(target))
		} else {
			o.Result, o.Message = ResultUnchanged, "nothing new"
		}
		return o, served
	}
	if target == "" {
		o.Result, o.Message = ResultUnchanged, "nothing to apply"
		return o, served
	}
	if st.Applied != nil && st.Applied.Commit == target && a.Now().Sub(st.Applied.At) <= ReapplyAfter {
		o.Result, o.Message = ResultUnchanged, fmt.Sprintf("%s is applied", short(target))
		return o, served
	}
	slog.Info("applying", "host", cfg.Host, "commit", target)
	err := Apply(ctx, a.Ansible, ReleaseDir(cfg.StateDir, target), cfg.Host, cfg.AgeKey, a.Out, a.Out)
	if err != nil {
		slog.Error("apply failed", "host", cfg.Host, "commit", target, "err", err)
		o.Result, o.Message = ResultFailed, fmt.Sprintf("apply of %s failed: %v", short(target), err)
		return o, served
	}
	rec := Record{Commit: target, At: a.now()}
	if st.Verified != nil && st.Verified.Commit == target {
		rec.Time = st.Verified.Time
	}
	st.Applied = &rec
	if err := st.Save(cfg.StateDir); err != nil { // before anything else: what was applied must not be forgotten
		slog.Error("cannot record the applied bundle", "err", err)
	}
	o.Result, o.Message = ResultOK, fmt.Sprintf("applied %s", short(target))
	return o, served
}

type bundleStatus int

const (
	statusNew   bundleStatus = iota // strictly newer than everything seen: extracted and recorded
	statusSame                      // the commit and time already applied or verified
	statusOlder                     // not newer: ignored
)

// accept decrypts, verifies and extracts a bundle, applying the forward-only rule. A RejectError means a check failed.
func (a *Agent) accept(ctx context.Context, st *State, body []byte) (bundle.Statement, bundleStatus, error) {
	files, err := OpenBundle(body, a.ID)
	if err != nil {
		return bundle.Statement{}, 0, err
	}
	if err := VerifySignature(ctx, a.SSHKeygen, a.Cfg.Signers, a.Cfg.StateDir, files.Statement, files.Signature); err != nil {
		return bundle.Statement{}, 0, err
	}
	stmt, err := CheckStatement(files.Statement, a.Cfg.Repo, files.Tarball)
	if err != nil {
		return stmt, 0, err
	}
	// Forward only: CI signs only the current main, so a later statement time means a later main (docs/agent.md).
	// The line is the newest time the agent has applied or verified.
	var hw int64
	same := false
	for _, r := range []*Record{st.Applied, st.Verified} {
		if r == nil {
			continue
		}
		hw = max(hw, r.Time.Unix())
		if r.Commit == stmt.Commit && r.Time.Unix() == stmt.Time {
			same = true
		}
	}
	switch {
	case same:
		if _, err := os.Stat(ReleaseDir(a.Cfg.StateDir, stmt.Commit)); err != nil {
			if _, err := Extract(a.Cfg.StateDir, stmt.Commit, files.Tarball); err != nil {
				return stmt, 0, err
			}
		}
		return stmt, statusSame, nil
	case stmt.Time <= hw:
		slog.Warn("bundle is not newer than what was applied, ignored", "commit", stmt.Commit, "time", stmt.Time, "newest", hw)
		return stmt, statusOlder, nil
	}
	if _, err := Extract(a.Cfg.StateDir, stmt.Commit, files.Tarball); err != nil {
		return stmt, 0, err
	}
	now := a.now()
	st.Verified = &Record{Commit: stmt.Commit, Time: time.Unix(stmt.Time, 0).UTC(), At: now}
	if err := st.Save(a.Cfg.StateDir); err != nil {
		return stmt, 0, fmt.Errorf("write state: %w", err)
	}
	slog.Info("bundle verified", "host", a.Cfg.Host, "commit", stmt.Commit)
	return stmt, statusNew, nil
}

// report sends the outcome to the hub that served the bundle, then to the others until one accepts it.
func (a *Agent) report(ctx context.Context, first *Hub, o Outcome) bool {
	rep := ReportBody{AppliedCommit: o.AppliedCommit, Result: o.Result, Message: o.Message, Time: a.Now().UTC().Format(time.RFC3339)}
	order := make([]*Hub, 0, len(a.Hubs))
	if first != nil {
		order = append(order, first)
	}
	for _, h := range a.Hubs {
		if h != first {
			order = append(order, h)
		}
	}
	for _, h := range order {
		if ctx.Err() != nil {
			return false
		}
		if err := h.Report(ctx, a.Cfg.Host, a.ID, rep); err != nil {
			slog.Warn("report not delivered", "hub", h.URL, "err", err)
			continue
		}
		slog.Debug("report delivered", "hub", h.URL)
		return true
	}
	return false
}

// now is the clock to the second, in UTC (the form of every time in the state and in the JSON).
func (a *Agent) now() time.Time { return a.Now().UTC().Truncate(time.Second) }

func short(commit string) string {
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}

// truncate cuts s to at most n bytes on a rune boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// Loop runs cycles until ctx ends, waiting Interval (plus or minus 10 %) between them. The caller holds the lock.
func (a *Agent) Loop(ctx context.Context) {
	for {
		if _, err := a.Cycle(ctx); err != nil {
			slog.Error("cycle failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(Jitter(a.Cfg.Interval)):
		}
	}
}

// Jitter is d with a random difference of up to 10 %.
func Jitter(d time.Duration) time.Duration {
	return d + time.Duration((rand.Float64()*0.2-0.1)*float64(d))
}
