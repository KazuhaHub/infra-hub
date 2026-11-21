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
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/KazuhaHub/infra-hub/internal/bundle"
	"github.com/KazuhaHub/infra-hub/internal/githubapp"
)

// Results of a cycle (and of its report).
const (
	ResultOK          = "ok"          // applied
	ResultVerified    = "verified"    // fetched and verified, nothing applied (verify mode)
	ResultUnchanged   = "unchanged"   // nothing new
	ResultFailed      = "failed"      // ansible failed
	ResultRejected    = "rejected"    // a signature, hash or format check failed
	ResultUnreachable = "unreachable" // no hub gave a bundle (and the GitHub fallback, if set, did not either)
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

	ghMu     sync.Mutex
	ghSource *githubapp.Source // the GitHub App credential, made on first use

	// SSHKeygen and Ansible are the programs to run (defaults ssh-keygen and ansible-playbook, found through PATH).
	SSHKeygen, Ansible string
	// InfraLock and InfraApplied are infra-pull's lock and applied record; LockTimeout bounds the wait for the lock.
	InfraLock, InfraApplied string
	LockTimeout             time.Duration
	// MinCycleGap is the shortest time between the start of a cycle and the start of one that a kick causes (default
	// DefaultMinCycleGap).
	MinCycleGap time.Duration
	// Out receives ansible's output (default os.Stderr, which is the journal under systemd).
	Out io.Writer
	Now func() time.Time

	noStartDelay bool // tests: no random delay before the first cycle of Loop

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

// ErrFloorUnknown means infra-pull's record has applied_at 0: infra-pull seeded its floor but has not applied anything
// yet, so there is no time to start from.
var ErrFloorUnknown = errors.New("waiting for infra-pull to record an applied time")

// ErrInterrupted is the error of a cycle that was stopped from outside.
var ErrInterrupted = errors.New("interrupted")

// LegacyFloor reads infra-pull's applied record: "<commit> <unix applied_at>". A missing file is no floor (0). An
// applied_at of 0 (what infra-pull writes when it seeds its floor) is ErrFloorUnknown. A file that does not have the
// form is an error that the cycle reports as result failed.
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
		return 0, fmt.Errorf("%s is malformed: want \"<commit> <unix applied_at>\"", a.InfraApplied)
	}
	n, err := strconv.ParseInt(f[1], 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%s is malformed: applied_at %q is not a unix time", a.InfraApplied, f[1])
	}
	if n == 0 {
		return 0, ErrFloorUnknown
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
	var o Outcome
	var served *Hub
	var rejs []rejection
	started := a.Now()
	pre := false
	if st.Verified == nil && st.Applied == nil {
		// A fresh state: infra-pull's record gives the floor, read here and only here (never at startup).
		switch a.floor, err = a.LegacyFloor(); {
		case errors.Is(err, ErrFloorUnknown):
			o, pre = Outcome{Result: ResultUnchanged, Message: err.Error()}, true
		case err != nil:
			o, pre = Outcome{Result: ResultFailed, Message: err.Error()}, true
		}
	}
	if !pre {
		o, served, rejs = a.fetchAndApply(ctx, &st)
	}
	if st.Applied != nil {
		o.AppliedCommit = st.Applied.Commit
	}
	if ctx.Err() != nil {
		// Stopped from outside: what the cycle found is not a result, and the last real one stays in the state.
		slog.Info("interrupted", "host", a.Cfg.Host, "result", o.Result)
		return o, fmt.Errorf("%w: %v", ErrInterrupted, ctx.Err())
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
		fallback  *Hub // the first hub whose answer was "nothing new" (304, the same bundle, an older one)
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
		if notModified || status != statusNew {
			// Nothing new from this hub, but another may be ahead of it (a mirror that lags): ask on, and fall back to
			// what is already verified only when every hub has answered.
			slog.Debug("nothing new", "hub", hub.URL)
			if fallback == nil {
				fallback = hub
			}
			continue
		}
		served, newBundle = hub, true
		break
	}
	if served == nil {
		served = fallback
	}
	if served == nil {
		var o Outcome
		if len(rejs) > 0 {
			var notes []string
			for _, r := range rejs {
				notes = append(notes, r.note())
			}
			o = Outcome{Result: ResultRejected, Message: strings.Join(notes, "; "), Hub: rejs[0].hub.URL}
		} else {
			o = Outcome{Result: ResultUnreachable, Message: fmt.Sprintf("no hub gave a bundle (%d of %d tried)", hubErrs, len(a.Hubs))}
		}
		if cfg.GitHubRepo == "" || ctx.Err() != nil {
			return o, nil, rejs
		}
		return a.githubFallback(ctx, st, o), nil, rejs
	}
	target := ""
	if st.Verified != nil {
		target = st.Verified.Commit
	}
	o := a.decide(ctx, st, served.URL, target, newBundle)
	for _, r := range rejs {
		o.Message += "; " + r.note()
	}
	return o, served, rejs
}

// githubFallback is what a cycle does when no hub gave a bundle (every hub unreachable, failing or rejected) and the
// GitHub fallback is configured: it takes main-attestation straight from GitHub and runs the same checks as for a hub's
// bundle. failed is the outcome the hubs alone gave; it stays the result when GitHub does not help.
func (a *Agent) githubFallback(ctx context.Context, st *State, failed Outcome) Outcome {
	slog.Warn("no hub gave a bundle, trying the GitHub fallback", "host", a.Cfg.Host, "repo", a.Cfg.GitHubRepo, "hubs", failed.Message)
	files, err := a.fetchGitHub(ctx)
	var be *githubBundleError
	if errors.As(err, &be) {
		slog.Warn("bundle from GitHub is not usable", "err", err)
		return Outcome{Result: ResultRejected, Message: "bundle from GitHub (no hub gave one) rejected: " + be.Error() + "; " + failed.Message, Hub: GitHubSource}
	}
	if err != nil {
		slog.Warn("GitHub fallback failed", "err", err)
		failed.Message += "; GitHub fallback: " + err.Error()
		return failed
	}
	_, status, err := a.acceptFiles(ctx, st, files)
	var rj *RejectError
	var le *localError
	switch {
	case errors.As(err, &rj):
		slog.Warn("bundle from GitHub rejected", "err", err)
		return Outcome{Result: ResultRejected, Message: "bundle from GitHub (no hub gave one) rejected: " + rj.Reason + "; " + failed.Message, Hub: GitHubSource}
	case errors.As(err, &le):
		return Outcome{Result: ResultFailed, Message: "cannot process the bundle from GitHub: " + le.Error(), Hub: GitHubSource}
	case err != nil:
		failed.Message += "; GitHub fallback: " + err.Error()
		return failed
	}
	slog.Warn("using the bundle from GitHub because no hub gave one", "host", a.Cfg.Host, "status", status)
	target := ""
	if st.Verified != nil {
		target = st.Verified.Commit
	}
	o := a.decide(ctx, st, GitHubSource, target, status == statusNew)
	// failed.Message already says "no hub gave a bundle (n of m tried)" when the hubs were unreachable; a rejection note
	// does not.
	why := failed.Message
	if !strings.HasPrefix(why, "no hub gave a bundle") {
		why = "no hub gave a bundle (" + why + ")"
	}
	o.Message = "from GitHub, " + why + ": " + o.Message
	return o
}

// decide is the second half of a cycle: with a verified bundle in hand, apply it (apply mode) or leave it (verify mode).
func (a *Agent) decide(ctx context.Context, st *State, source, target string, newBundle bool) Outcome {
	cfg := a.Cfg
	o := Outcome{Hub: source}
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
	// infra-pull's protocol: the holder writes lock.since (epoch seconds) atomically after getting the lock, and removes it
	// when it lets go; a waiting infra-pull reads its age to tell a stuck holder from a working one.
	since := filepath.Join(filepath.Dir(a.InfraLock), "lock.since")
	if err := writeSince(since, a.Now().Unix()); err != nil {
		slog.Warn("cannot write lock.since", "path", since, "err", err)
	}
	defer removeSince(since)
	slog.Info("applying", "host", cfg.Host, "commit", target)
	if err := Apply(ctx, a.Ansible, ReleaseDir(cfg.StateDir, target), cfg.Host, cfg.AgeKey, RestartFile(cfg.StateDir), a.Out); err != nil {
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

// writeSince writes "<epoch>\n" to path through path+".new" and a rename, as infra-pull does.
func writeSince(path string, epoch int64) error {
	if err := os.WriteFile(path+".new", []byte(strconv.FormatInt(epoch, 10)+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(path+".new", path)
}

func removeSince(path string) {
	os.Remove(path)
	os.Remove(path + ".new")
}

type bundleStatus int

const (
	statusNew   bundleStatus = iota // strictly newer than everything seen: extracted and recorded
	statusSame                      // exactly the newest verified bundle (commit and time)
	statusOlder                     // not newer: ignored
)

// accept decrypts a hub's answer and checks it as acceptFiles does. A RejectError means a check failed, a localError a
// fault of this machine.
func (a *Agent) accept(ctx context.Context, st *State, body io.Reader) (bundle.Statement, bundleStatus, error) {
	files, err := OpenBundle(body, a.ID)
	if err != nil {
		return bundle.Statement{}, 0, err
	}
	return a.acceptFiles(ctx, st, files)
}

// acceptFiles verifies and extracts the three files of a bundle (from a hub, decrypted, or from GitHub) and applies the
// forward-only rule. The checks are the same for both sources.
func (a *Agent) acceptFiles(ctx context.Context, st *State, files bundle.Files) (bundle.Statement, bundleStatus, error) {
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
	for _, r := range rejs {
		if len(rep.RejectedHubs) < 8 && !contains(rep.RejectedHubs, r.hub.URL) {
			rep.RejectedHubs = append(rep.RejectedHubs, r.hub.URL)
		}
	}
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

// Loop runs cycles until ctx ends or a configuration run asks for a restart, waiting Interval (plus or minus 10 %)
// between them. The first cycle starts after a random delay of up to min(Interval, 60 s), so a fleet that restarts
// together does not call the hubs together. The caller holds the lock. It returns true when it stopped for a restart
// request: the caller then exits and systemd starts the new binary, settings and unit.
func (a *Agent) Loop(ctx context.Context) bool {
	// This process already runs whatever a request left before it started asked for.
	if err := os.Remove(RestartFile(a.Cfg.StateDir)); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Warn("cannot remove the restart request", "err", err)
	}
	first := min(a.Cfg.Interval, time.Minute)
	if a.noStartDelay {
		first = 0
	}
	select {
	case <-ctx.Done():
		return false
	case <-time.After(time.Duration(rand.Float64() * float64(first))):
	}
	failed := "" // the commit whose apply failed in the last cycle ("" if it did not)
	seen := ""   // the newest commit a hub told us about by a kick; waiting continues from it, not from the verified one
	for {
		o, err := a.Cycle(ctx)
		if err != nil && ctx.Err() == nil {
			slog.Error("cycle failed", "err", err)
		}
		cycleEnd := time.Now()
		failed = ""
		if o.Result == ResultFailed {
			if st, err := LoadState(a.Cfg.StateDir); err == nil && st.Verified != nil {
				failed = st.Verified.Commit
			}
		}
		if ctx.Err() == nil && a.takeRestartRequest() {
			return true
		}
		if ctx.Err() != nil {
			return false
		}
		// Wait for the interval, or for a hub to say the bundle changed (kick.go). The interval is the upper bound.
		until := time.Now().Add(Jitter(a.Cfg.Interval))
		etag := a.kickEtag(seen)
		kicked, commit := a.waitKick(ctx, etag, until)
		if kicked && commit == failed {
			// The kick names the commit whose apply just failed: another cycle now would only run ansible again, back to
			// back. The normal interval decides when the retry happens.
			slog.Info("a hub names the commit whose apply failed, retrying at the next interval", "host", a.Cfg.Host, "commit", commit)
			seen = commit
			pause(ctx, until, time.Until(until))
		} else if kicked {
			seen = commit
			slog.Info("a hub has a new bundle, starting a cycle", "host", a.Cfg.Host, "commit", commit)
			// Never closer than the minimum gap after the last cycle ended (and never later than the interval would be).
			gapEnd := cycleEnd.Add(min(a.minGap(), a.Cfg.Interval))
			pause(ctx, gapEnd, time.Until(gapEnd))
		} else {
			seen = ""
			pause(ctx, until, time.Until(until))
		}
		if ctx.Err() != nil {
			return false
		}
	}
}

// kickEtag is the commit to wait away from: the verified one, unless a kick already named a newer one (that the last
// cycle could not verify; asking again from the verified commit would answer at once and loop).
func (a *Agent) kickEtag(seen string) string {
	st, err := LoadState(a.Cfg.StateDir)
	if err != nil {
		return seen
	}
	if st.Verified != nil && (seen == "" || seen == st.Verified.Commit) {
		return st.Verified.Commit
	}
	return seen
}

// takeRestartRequest reports whether the restart request file exists and removes it. A file that cannot be removed is
// not honoured: the agent would otherwise exit again after every cycle.
func (a *Agent) takeRestartRequest() bool {
	p := RestartFile(a.Cfg.StateDir)
	if _, err := os.Lstat(p); err != nil {
		return false
	}
	if err := os.Remove(p); err != nil {
		slog.Error("restart requested, but the request cannot be removed; not restarting", "path", p, "err", err)
		return false
	}
	slog.Info("restarting: the configuration run asked for it (new binary, settings or unit)", "host", a.Cfg.Host)
	return true
}

// Jitter is d with a random difference of up to 10 %.
func Jitter(d time.Duration) time.Duration {
	return d + time.Duration((rand.Float64()*0.2-0.1)*float64(d))
}
