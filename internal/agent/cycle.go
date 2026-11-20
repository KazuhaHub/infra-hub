package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math/rand/v2"
	"os"
	"regexp"
	"strconv"
	"strings"
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

// Defaults of the files shared with infra-pull.
const (
	// DefaultInfraLock is the lock infra-pull and the bootstrap hold while they apply: the agent holds it while ansible runs.
	DefaultInfraLock = "/var/lib/infra/lock"
	// DefaultInfraApplied is infra-pull's record of what it applied: "<commit> <unix applied_at>".
	DefaultInfraApplied = "/var/lib/infra/applied"
	// DefaultLockTimeout is how long the agent waits for DefaultInfraLock.
	DefaultLockTimeout = 30 * time.Minute
)

// Agent runs cycles for one host.
type Agent struct {
	Cfg  Config
	ID   *Identity
	Hubs []*Hub

	// SSHKeygen and Ansible are the programs to run (defaults ssh-keygen and ansible-playbook, found through PATH).
	SSHKeygen, Ansible string
	// InfraLock and InfraApplied are infra-pull's lock and applied record; LockTimeout bounds the wait for the lock.
	InfraLock, InfraApplied string
	LockTimeout             time.Duration
	// Out receives ansible's output (default os.Stderr, which is the journal under systemd).
	Out io.Writer
	Now func() time.Time

	floor int64 // minimum statement time seeded from InfraApplied (0: none); only used while the state has no mark
}

// New builds an agent from a validated configuration and its age identity.
func New(cfg Config, id *Identity) (*Agent, error) {
	a := &Agent{Cfg: cfg, ID: id, SSHKeygen: "ssh-keygen", Ansible: "ansible-playbook", Out: os.Stderr, Now: time.Now,
		InfraLock: DefaultInfraLock, InfraApplied: DefaultInfraApplied, LockTimeout: DefaultLockTimeout}
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

// LegacyFloor reads infra-pull's applied record: "<commit> <unix applied_at>". A missing file is no floor (0). A file
// that does not have that form is a ConfigError.
func (a *Agent) LegacyFloor() (int64, error) {
	data, err := os.ReadFile(a.InfraApplied)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	f := strings.Fields(string(data))
	if len(f) != 2 || !commitHex.MatchString(f[0]) {
		return 0, configErrorf("%s is malformed: want \"<commit> <unix applied_at>\"", a.InfraApplied)
	}
	n, err := strconv.ParseInt(f[1], 10, 64)
	if err != nil || n < 1 {
		return 0, configErrorf("%s is malformed: applied_at %q is not a unix time", a.InfraApplied, f[1])
	}
	return n, nil
}

var commitHex = regexp.MustCompile(`^[0-9a-f]{40}$`)

// localError is a fault of this machine (state, disk, a program that cannot run), as opposed to a bundle that is bad.
type localError struct{ err error }

func (e *localError) Error() string { return e.err.Error() }
func (e *localError) Unwrap() error { return e.err }

func local(err error) error {
	var rj *RejectError
	if err == nil || errors.As(err, &rj) {
		return err
	}
	return &localError{err}
}

type rejection struct {
	hub    *Hub
	reason string
}

func (r rejection) note() string {
	return fmt.Sprintf("hub %s served a rejected bundle: %s", r.hub.URL, truncate(r.reason, 150))
}

// Cycle runs one fetch, verify, extract, apply and report. The error is for faults of the agent itself (the state
// cannot be read or written, the configuration is wrong) and for a cycle that was interrupted; every outcome that is
// about the bundle or the hubs is a Result instead.
func (a *Agent) Cycle(ctx context.Context) (Outcome, error) {
	if err := PrepareDir(a.Cfg.StateDir); err != nil {
		return Outcome{}, err
	}
	st, err := LoadState(a.Cfg.StateDir)
	if err != nil {
		return Outcome{}, err
	}
	a.floor = 0
	if st.Verified == nil && st.Applied == nil {
		if a.floor, err = a.LegacyFloor(); err != nil {
			return Outcome{}, err
		}
	}
	started := a.Now()
	o, served, rejs := a.fetchAndApply(ctx, &st)
	if st.Applied != nil {
		o.AppliedCommit = st.Applied.Commit
	}
	if ctx.Err() != nil {
		// Stopped from outside: what the cycle found is not a result, and the last real one stays in the state.
		slog.Info("interrupted", "host", a.Cfg.Host, "result", o.Result)
		return o, fmt.Errorf("interrupted: %w", ctx.Err())
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
	o.Reported = a.report(ctx, served, rejs, o)
	return o, nil
}

// fetchAndApply does the work of a cycle and updates st (it does not save the cycle's own fields).
func (a *Agent) fetchAndApply(ctx context.Context, st *State) (Outcome, *Hub, []rejection) {
	cfg := a.Cfg
	// A 304 only means something while the release it refers to is still on disk.
	etag := ""
	if st.Verified != nil {
		if _, err := os.Stat(ReleaseDir(cfg.StateDir, st.Verified.Commit)); err == nil {
			etag = st.Verified.Commit
		}
	}
	var (
		served    *Hub
		olderHub  *Hub // the first hub that served a bundle that is not newer
		newBundle bool
		rejs      []rejection
		hubErrs   int
	)
	for _, hub := range a.Hubs {
		if ctx.Err() != nil {
			break
		}
		var status bundleStatus
		notModified, err := hub.Bundle(ctx, cfg.Host, etag, func(r io.Reader) error {
			var err error
			_, status, err = a.accept(ctx, st, r)
			return err
		})
		var rj *RejectError
		var le *localError
		switch {
		case errors.As(err, &rj):
			rejs = append(rejs, rejection{hub, rj.Reason})
			slog.Warn("bundle rejected, trying the next hub", "hub", hub.URL, "err", err)
			continue
		case errors.As(err, &le):
			return Outcome{Result: ResultFailed, Message: "cannot process the bundle: " + le.Error(), Hub: hub.URL}, hub, rejs
		case err != nil:
			hubErrs++
			slog.Warn("hub did not give a bundle, trying the next", "hub", hub.URL, "err", err)
			continue
		}
		if notModified {
			served = hub
			slog.Debug("bundle unchanged", "hub", hub.URL)
			break
		}
		if status == statusOlder {
			// Another hub may be ahead of this one: ask on before falling back to what is already verified.
			if olderHub == nil {
				olderHub = hub
			}
			continue
		}
		served, newBundle = hub, status == statusNew
		break
	}
	if served == nil {
		served = olderHub
	}
	if served == nil {
		if len(rejs) > 0 {
			var notes []string
			for _, r := range rejs {
				notes = append(notes, r.note())
			}
			return Outcome{Result: ResultRejected, Message: strings.Join(notes, "; "), Hub: rejs[0].hub.URL}, nil, rejs
		}
		return Outcome{Result: ResultUnreachable, Message: fmt.Sprintf("no hub gave a bundle (%d of %d tried)", hubErrs, len(a.Hubs))}, nil, rejs
	}
	target := ""
	if st.Verified != nil {
		target = st.Verified.Commit
	}
	o := a.decide(ctx, st, served, target, newBundle)
	for _, r := range rejs {
		o.Message += "; " + r.note()
	}
	return o, served, rejs
}

// decide is the second half of a cycle: with a verified bundle in hand, apply it (apply mode) or leave it (verify mode).
func (a *Agent) decide(ctx context.Context, st *State, served *Hub, target string, newBundle bool) Outcome {
	cfg := a.Cfg
	o := Outcome{Hub: served.URL}
	if cfg.Mode == ModeVerify {
		if newBundle {
			o.Result, o.Message = ResultVerified, fmt.Sprintf("verified %s; verify mode, nothing applied", short(target))
		} else {
			o.Result, o.Message = ResultUnchanged, "nothing new"
		}
		return o
	}
	if target == "" {
		o.Result, o.Message = ResultUnchanged, "nothing to apply"
		return o
	}
	if st.Applied != nil && st.Applied.Commit == target && a.Now().Sub(st.Applied.At) <= ReapplyAfter {
		o.Result, o.Message = ResultUnchanged, fmt.Sprintf("%s is applied", short(target))
		return o
	}
	// infra-pull and the bootstrap hold this lock while they apply; two runs of ansible on one host must not overlap.
	lock, err := LockFile(ctx, a.InfraLock, a.LockTimeout)
	if err != nil {
		if errors.Is(err, ErrLockTimeout) {
			o.Result, o.Message = ResultFailed, fmt.Sprintf("another run holds %s", a.InfraLock)
			slog.Error("apply failed", "host", cfg.Host, "commit", target, "err", o.Message)
		} else {
			o.Result, o.Message = ResultFailed, fmt.Sprintf("cannot take %s: %v", a.InfraLock, err)
		}
		return o
	}
	defer lock.Close()
	slog.Info("applying", "host", cfg.Host, "commit", target)
	if err := Apply(ctx, a.Ansible, ReleaseDir(cfg.StateDir, target), cfg.Host, cfg.AgeKey, a.Out); err != nil {
		slog.Error("apply failed", "host", cfg.Host, "commit", target, "err", err)
		o.Result, o.Message = ResultFailed, fmt.Sprintf("apply of %s failed: %v", short(target), err)
		return o
	}
	// The applied record takes the statement time of the verified bundle it applied (target is always that one).
	rec := Record{Commit: target, Time: st.Verified.Time, At: a.now()}
	st.Applied = &rec
	if err := st.Save(cfg.StateDir); err != nil { // before anything else: what was applied must not be forgotten
		slog.Error("cannot record the applied bundle", "err", err)
	}
	o.Result, o.Message = ResultOK, fmt.Sprintf("applied %s", short(target))
	return o
}

type bundleStatus int

const (
	statusNew   bundleStatus = iota // strictly newer than everything seen: extracted and recorded
	statusSame                      // exactly the newest verified bundle (commit and time)
	statusOlder                     // not newer: ignored
)

// accept decrypts, verifies and extracts a bundle, applying the forward-only rule. A RejectError means a check failed,
// a localError a fault of this machine.
func (a *Agent) accept(ctx context.Context, st *State, body io.Reader) (bundle.Statement, bundleStatus, error) {
	files, err := OpenBundle(body, a.ID)
	if err != nil {
		return bundle.Statement{}, 0, err
	}
	if err := VerifySignature(ctx, a.SSHKeygen, a.Cfg.Signers, a.Cfg.StateDir, files.Statement, files.Signature); err != nil {
		return bundle.Statement{}, 0, local(err)
	}
	stmt, err := CheckStatement(files.Statement, a.Cfg.Repo, files.Tarball)
	if err != nil {
		return stmt, 0, err
	}
	// Forward only: CI signs only the current main, so a later statement time means a later main (docs/agent.md). The
	// line is the newest bundle the agent has verified (the applied one if there is no verified one); with neither, it is
	// the floor from infra-pull's record: a bundle signed at or after the time infra-pull applied is that main or newer.
	mark := st.Verified
	if mark == nil {
		mark = st.Applied
	}
	var hw int64
	switch {
	case mark != nil:
		hw = mark.Time.Unix()
	case a.floor > 0:
		hw = a.floor - 1
	}
	if mark != nil && mark.Commit == stmt.Commit && hw == stmt.Time {
		if _, err := os.Stat(ReleaseDir(a.Cfg.StateDir, stmt.Commit)); err != nil {
			if _, err := Extract(a.Cfg.StateDir, stmt.Commit, files.Tarball); err != nil {
				return stmt, 0, local(err)
			}
		}
		if st.Verified == nil { // the state had only an applied record: the verified one is this bundle
			st.Verified = &Record{Commit: stmt.Commit, Time: time.Unix(stmt.Time, 0).UTC(), At: a.now()}
		}
		return stmt, statusSame, nil
	}
	if stmt.Time <= hw {
		slog.Warn("bundle is not newer than what was verified, ignored", "commit", stmt.Commit, "statementTime", stmt.Time, "newest", hw)
		return stmt, statusOlder, nil
	}
	if _, err := Extract(a.Cfg.StateDir, stmt.Commit, files.Tarball); err != nil {
		return stmt, 0, local(err)
	}
	st.Verified = &Record{Commit: stmt.Commit, Time: time.Unix(stmt.Time, 0).UTC(), At: a.now()}
	if err := st.Save(a.Cfg.StateDir); err != nil {
		return stmt, 0, local(fmt.Errorf("write state: %w", err))
	}
	slog.Info("bundle verified", "host", a.Cfg.Host, "commit", stmt.Commit)
	return stmt, statusNew, nil
}

// report sends the outcome to the hubs. Normally that is the hub that served the bundle, then the others until one
// accepts it. When the serving hub is not the first in the token, nobody served, or a hub served a rejected bundle (whose
// note is in the message), every hub gets it, so the first and the rejecting hub also learn what happened.
func (a *Agent) report(ctx context.Context, served *Hub, rejs []rejection, o Outcome) bool {
	rep := ReportBody{AppliedCommit: o.AppliedCommit, Result: o.Result, Message: o.Message, Time: a.Now().UTC().Format(time.RFC3339)}
	all := served == nil || len(a.Hubs) > 0 && served != a.Hubs[0] || len(rejs) > 0
	order := make([]*Hub, 0, len(a.Hubs))
	if served != nil {
		order = append(order, served)
	}
	for _, h := range a.Hubs {
		if h != served {
			order = append(order, h)
		}
	}
	delivered := false
	for _, h := range order {
		if ctx.Err() != nil {
			break
		}
		if err := h.Report(ctx, a.Cfg.Host, a.ID, rep); err != nil {
			slog.Warn("report not delivered", "hub", h.URL, "err", err)
			continue
		}
		slog.Debug("report delivered", "hub", h.URL)
		delivered = true
		if !all {
			break
		}
	}
	return delivered
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

// Loop runs cycles until ctx ends, waiting Interval (plus or minus 10 %) between them. The first cycle starts after a
// random delay of up to min(Interval, 60 s), so a fleet that restarts together does not call the hubs together. The caller
// holds the lock.
func (a *Agent) Loop(ctx context.Context) {
	first := min(a.Cfg.Interval, time.Minute)
	select {
	case <-ctx.Done():
		return
	case <-time.After(time.Duration(rand.Float64() * float64(first))):
	}
	for {
		if _, err := a.Cycle(ctx); err != nil && ctx.Err() == nil {
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
