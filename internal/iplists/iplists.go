package iplists

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/atomicfile"
)

// IP lists on the hub. A provider is a named source (URL, format) that the hub downloads every few hours; a list is
// the union of some providers and some manual entries, and is served to the hosts the config names (`iplist <name>`
// over the SSH server). Everything comes from the config, which is rendered from the inventory; nothing a client
// sends can add a provider, a list or an entry.

const (
	// IPListInterval is how often a provider is refreshed.
	IPListInterval = 6 * time.Hour
	// IPBackoffBase doubles per consecutive failure, up to the refresh interval.
	IPBackoffBase = 15 * time.Minute
	// Change guard: an update that removes more than GuardRemovePct or adds more than GuardAddPct (percent of the
	// entries the provider had) is held until `infra-hub iplist accept <provider>`.
	GuardRemovePct = 30
	GuardAddPct    = 50
	// A provider whose last success is older than StaleAfter, or that failed FailingAfterRuns times in a row, is
	// reported in the warnings that travel with the list.
	StaleAfter       = 24 * time.Hour
	FailingAfterRuns = 3
	// ipTick is how often the manager looks for due providers and accepted changes.
	ipTick = 30 * time.Second
)

var NameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// IPList is a named list: providers plus manual entries, served to Hosts.
type IPList struct {
	Providers []string `json:"providers"`
	Manual    []string `json:"manual"`
	// Hosts may fetch this list. Rendered from the hosts that have an output for it in the inventory.
	Hosts []string `json:"hosts"`
}

// ProviderState is what the hub remembers about one provider (<dir>/<name>.json): the last good list and how the
// attempts went. The last good list is only ever replaced by a list that passed every check.
type ProviderState struct {
	CIDRs       []string  `json:"cidrs"`
	LastSuccess time.Time `json:"last_success"` // last download that passed validation (also when held)
	LastAttempt time.Time `json:"last_attempt"`
	LastChange  time.Time `json:"last_change"` // when CIDRs last changed
	LastError   string    `json:"last_error,omitempty"`
	Failures    int       `json:"failures"` // consecutive failed attempts
	NextAttempt time.Time `json:"next_attempt"`
	Held        bool      `json:"held"`
	Pending     []string  `json:"pending,omitempty"` // the held candidate, served nowhere
	HeldReason  string    `json:"held_reason,omitempty"`
}

// IPManager collects the providers and serves the lists.
type IPManager struct {
	Dir     string
	Sources map[string]IPSource
	Lists   map[string]IPList
	Client  *http.Client
	Now     func() time.Time

	mu sync.Mutex
}

func (m *IPManager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *IPManager) client() *http.Client {
	if m.Client != nil {
		return m.Client
	}
	return &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" || len(via) >= 5 {
			return errors.New("redirect refused")
		}
		return nil
	}}
}

func (m *IPManager) path(provider string) string { return filepath.Join(m.Dir, provider+".json") }

func (m *IPManager) used() []string { // providers some list uses, in name order
	set := map[string]bool{}
	for _, l := range m.Lists {
		for _, p := range l.Providers {
			set[p] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// loadProvider reads a provider's state. A missing file is a fresh provider (not an error); a file that cannot be read
// or parsed is an error and is never treated as empty or as a first list: the caller must neither serve nor overwrite it.
func loadProvider(path string) (ProviderState, error) {
	var st ProviderState
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return ProviderState{}, err
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return ProviderState{}, fmt.Errorf("corrupt state file: %v", err)
	}
	return st, nil
}

func (m *IPManager) save(provider string, st ProviderState) error {
	if err := os.MkdirAll(m.Dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(m.path(provider), append(data, '\n'), 0o600)
}

// ipBackoff is the wait after the failures-th consecutive failure (1-based): 15 minutes, doubling, at most IPListInterval.
func ipBackoff(failures int) time.Duration {
	d := IPBackoffBase
	for i := 1; i < failures && d < IPListInterval; i++ {
		d *= 2
	}
	if d > IPListInterval {
		d = IPListInterval
	}
	return d
}

// guard says whether replacing old by new must wait for a person, and why. It looks at the number of entries and at
// the address space they cover (per family), so one wide prefix cannot slip through as "one entry".
func guard(old, cur []string) (string, bool) {
	oldSet, curSet := map[string]bool{}, map[string]bool{}
	for _, c := range old {
		oldSet[c] = true
	}
	for _, c := range cur {
		curSet[c] = true
	}
	var added, removed int
	oldSpace := map[string]float64{}
	addSpace := map[string]float64{}
	remSpace := map[string]float64{}
	fam := func(c string) string {
		if strings.Contains(c, ":") {
			return "IPv6"
		}
		return "IPv4"
	}
	w := func(c string) float64 {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return 0
		}
		return weight(p)
	}
	for _, c := range old {
		oldSpace[fam(c)] += w(c)
		if !curSet[c] {
			removed++
			remSpace[fam(c)] += w(c)
		}
	}
	for _, c := range cur {
		if !oldSet[c] {
			added++
			addSpace[fam(c)] += w(c)
		}
	}
	switch {
	case removed*100 > GuardRemovePct*len(old):
		return fmt.Sprintf("update would remove %d of %d entries (limit %d%%)", removed, len(old), GuardRemovePct), true
	case added*100 > GuardAddPct*len(old):
		return fmt.Sprintf("update would add %d to %d entries (limit %d%%)", added, len(old), GuardAddPct), true
	}
	for _, f := range []string{"IPv4", "IPv6"} {
		if oldSpace[f] > 0 && remSpace[f]*100 > GuardRemovePct*oldSpace[f] {
			return fmt.Sprintf("update would remove more than %d%% of the %s address space", GuardRemovePct, f), true
		}
		if oldSpace[f] > 0 && addSpace[f]*100 > GuardAddPct*oldSpace[f] {
			return fmt.Sprintf("update would add more than %d%% to the %s address space", GuardAddPct, f), true
		}
		if oldSpace[f] == 0 && addSpace[f] > 0 {
			return fmt.Sprintf("update would add the first %s ranges", f), true
		}
	}
	return "", false
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// download fetches one source with a timeout and a size cap and returns the validated entries.
func (m *IPManager) download(ctx context.Context, src IPSource) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "infra-hub")
	resp, err := m.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	max := src.maxBytes()
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(body) > max {
		return nil, fmt.Errorf("answer is larger than %d bytes", max)
	}
	return ParseSource(src, body)
}

// Refresh downloads one provider and applies the result. Any failure keeps the last good list. A state file that
// cannot be read is left alone (and nothing is served from it): it is never treated as empty.
func (m *IPManager) Refresh(ctx context.Context, name string) {
	cur, err := m.download(ctx, m.Sources[name]) // not under the lock: serving and status never wait for a download
	m.mu.Lock()
	defer m.mu.Unlock()
	st, lerr := loadProvider(m.path(name))
	if lerr != nil {
		slog.Error("provider state unreadable, not touching it", "provider", name, "err", lerr)
		return
	}
	before := m.listsBefore(name)
	prevPending := ListVersion(st.Pending)
	hadState := len(st.CIDRs) > 0
	now := m.now()
	st.LastAttempt = now
	cause := "provider update"
	if err != nil {
		st.Failures++
		st.LastError = err.Error()
		st.NextAttempt = now.Add(ipBackoff(st.Failures))
		slog.Warn("provider fetch failed, kept the last list", "provider", name, "entries", len(st.CIDRs), "err", err)
	} else {
		st.Failures, st.LastError = 0, ""
		st.LastSuccess = now
		st.NextAttempt = now.Add(IPListInterval)
		switch {
		case len(st.CIDRs) == 0 || len(cur) == 0:
			st.CIDRs, st.LastChange = cur, now
			st.Held, st.Pending, st.HeldReason = false, nil, ""
			cause = "first fetch"
			slog.Info("first list stored", "provider", name, "entries", len(cur))
		case sameStrings(cur, st.CIDRs):
			st.Held, st.Pending, st.HeldReason = false, nil, ""
		default:
			if why, hold := guard(st.CIDRs, cur); hold {
				st.Held, st.Pending, st.HeldReason = true, cur, why
				slog.Warn("update held, still serving the last list", "provider", name, "reason", why, "entries", len(st.CIDRs), "hint", "infra-hub iplist accept "+name)
			} else {
				slog.Info("list changed", "provider", name, "from", len(st.CIDRs), "to", len(cur))
				st.CIDRs, st.LastChange = cur, now
				st.Held, st.Pending, st.HeldReason = false, nil, ""
			}
		}
	}
	if err := m.save(name, st); err != nil {
		slog.Error("cannot save provider state", "provider", name, "err", err)
		return
	}
	_ = hadState
	m.recordChange(name, before, cause, st)
	if st.Held && ListVersion(st.Pending) != prevPending {
		m.recordHeld(name, st)
	}
}

func (m *IPManager) acceptDir() string { return filepath.Join(m.Dir, "accept") }

// afterRootOpen is called by RequestAccept once the state directory is open; tests use it to make the path unreachable
// (like /var/lib/private, which only root can traverse) and so prove that nothing is looked up by path afterwards.
var afterRootOpen = func() {}

// RequestAccept is what `infra-hub iplist accept` does: it records which held update (by the version of its entries) a
// person has reviewed. The running hub applies it on its next tick, so the hub is the only writer of provider files.
//
// Run as root it first opens the real state directory (the path usually runs through /var/lib/private, which only root
// can enter) as a directory handle, and only then becomes the directory's owner (the hub's dynamic user). Everything
// after that is done relative to the handle (os.Root), which cannot be walked out of through a symlink, so nothing is
// written as root and nothing is reached through a path the hub user could swap.
func RequestAccept(dir, provider string) (ProviderState, error) {
	if !NameRe.MatchString(provider) {
		return ProviderState{}, errors.New("not a provider name")
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return ProviderState{}, err
	}
	root, err := os.OpenRoot(real)
	if err != nil {
		return ProviderState{}, err
	}
	defer root.Close()
	if fi, err := root.Stat("."); err == nil && os.Geteuid() == 0 {
		if sys, ok := fi.Sys().(*syscall.Stat_t); ok && sys.Uid != 0 {
			if err := dropTo(int(sys.Uid), int(sys.Gid)); err != nil {
				return ProviderState{}, fmt.Errorf("cannot drop root: %v", err)
			}
		}
	}
	afterRootOpen()
	var st ProviderState
	data, err := root.ReadFile(provider + ".json")
	if errors.Is(err, os.ErrNotExist) {
		return st, fmt.Errorf("provider %s has no held update", provider)
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return ProviderState{}, fmt.Errorf("corrupt state file: %v", err)
	}
	if !st.Held {
		return st, fmt.Errorf("provider %s has no held update", provider)
	}
	if fi, err := root.Lstat("accept"); err == nil && !fi.IsDir() { // a symlink planted where the directory should be
		return st, errors.New("accept is not a plain directory")
	}
	if err := root.MkdirAll("accept", 0o700); err != nil {
		return st, err
	}
	tmp := "accept/." + provider + ".tmp"
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return st, err
	}
	if _, err := f.WriteString(ListVersion(st.Pending) + "\n"); err != nil {
		f.Close()
		return st, err
	}
	if err := f.Close(); err != nil {
		return st, err
	}
	return st, root.Rename(tmp, "accept/"+provider)
}

func dropTo(uid, gid int) error {
	if err := syscall.Setgroups([]int{}); err != nil {
		return err
	}
	if err := syscall.Setgid(gid); err != nil {
		return err
	}
	return syscall.Setuid(uid)
}

// applyAccepts applies the requests that match the held update they were made for; others are dropped.
func (m *IPManager) applyAccepts() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, name := range m.used() {
		f := filepath.Join(m.acceptDir(), name)
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		os.Remove(f)
		st, err := loadProvider(m.path(name))
		if err != nil || !st.Held || strings.TrimSpace(string(data)) != ListVersion(st.Pending) {
			slog.Warn("ignored an accept request that does not match the held update", "provider", name)
			continue
		}
		slog.Info("held update accepted", "provider", name, "from", len(st.CIDRs), "to", len(st.Pending))
		before := m.listsBefore(name)
		st.CIDRs, st.LastChange = st.Pending, m.now()
		st.Held, st.Pending, st.HeldReason = false, nil, ""
		if err := m.save(name, st); err != nil {
			slog.Error("cannot save provider state", "provider", name, "err", err)
			continue
		}
		m.recordChange(name, before, "accept", st)
	}
}

// RunOnce applies accept requests and refreshes every provider that is due.
func (m *IPManager) RunOnce(ctx context.Context) {
	m.applyAccepts()
	for _, name := range m.used() {
		if ctx.Err() != nil {
			return
		}
		m.mu.Lock()
		st, err := loadProvider(m.path(name))
		due := err == nil && !m.now().Before(st.NextAttempt) // an unreadable state file is not overwritten
		m.mu.Unlock()
		if due {
			m.Refresh(ctx, name)
		}
	}
}

func (m *IPManager) Run(ctx context.Context) {
	for {
		m.RunOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(ipTick):
		}
	}
}

// IPListPayload is the whole output of `iplist <name>`: one JSON object on one line.
type IPListPayload struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`   // ListVersion(CIDRs)
	Generated string   `json:"generated"` // RFC 3339, UTC
	CIDRs     []string `json:"cidrs"`
	// Warnings are things a person should look at (held update, failing or stale provider, unusable state). Hosts mail
	// them; they never change what the list holds and are not part of Version.
	Warnings []string `json:"warnings"`
}

// IPListSource is what the SSH server needs.
type IPListSource interface {
	Allowed(name, host string) bool
	Serve(name string) (IPListPayload, error)
}

func (m *IPManager) Allowed(name, host string) bool {
	l, ok := m.Lists[name]
	if !ok {
		return false
	}
	for _, h := range l.Hosts {
		if h == host {
			return true
		}
	}
	return false
}

// printable keeps a text short and plain ASCII (it ends up in a reply and in mails).
func printable(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			b[i] = ' '
		}
	}
	if len(b) > 160 {
		b = b[:160]
	}
	return string(b)
}

// MaxWarnings is the most warnings a reply carries (the client accepts 20): the first 19 and "more:all and N more".
const MaxWarnings = 20

// warnings lists what a person should look at for the providers of one list. Every warning is "kind:provider detail":
// the first word (kind:provider, one of held, failing, stale, state_error) is the stable identity of the issue, which is
// what hosts and the hourly mailer deduplicate on; everything after it (counts, error text, times) is only for reading.
// The result is sorted, without duplicates and at most MaxWarnings long.
func (m *IPManager) warnings(l IPList) []string {
	set := map[string]bool{}
	now := m.now()
	for _, p := range l.Providers {
		st, err := loadProvider(m.path(p))
		if err != nil {
			set[printable(fmt.Sprintf("state_error:%s state file unusable (%v); nothing new is served from it", p, err))] = true
			continue
		}
		if st.Held {
			set[printable(fmt.Sprintf("held:%s update held (%s); the previous list is still served; see infra-hub iplist accept", p, st.HeldReason))] = true
		}
		if st.Failures >= FailingAfterRuns {
			set[printable(fmt.Sprintf("failing:%s %d attempts in a row (%s)", p, st.Failures, st.LastError))] = true
		}
		if !st.LastSuccess.IsZero() && now.Sub(st.LastSuccess) > StaleAfter {
			set[printable(fmt.Sprintf("stale:%s last success %s is older than 24h", p, st.LastSuccess.UTC().Format(time.RFC3339)))] = true
		}
	}
	out := make([]string, 0, len(set))
	for w := range set {
		out = append(out, w)
	}
	sort.Strings(out)
	if len(out) > MaxWarnings {
		more := len(out) - (MaxWarnings - 1)
		out = append(out[:MaxWarnings-1], fmt.Sprintf("more:all and %d more", more))
		sort.Strings(out)
	}
	return out
}

// Serve builds the list: the last good entries of every provider plus the manual ones. A provider that has never
// delivered, or whose state file cannot be read, is an error (a CDN list without the CDN would lock the site out, and
// an unreadable state must not be served as empty); a provider that is only stale is not.
func (m *IPManager) Serve(name string) (IPListPayload, error) {
	l, ok := m.Lists[name]
	if !ok {
		return IPListPayload{}, errors.New("unknown list")
	}
	m.mu.Lock()
	all, err := m.compose(l, "", nil)
	warn := m.warnings(l)
	m.mu.Unlock()
	if err != nil {
		return IPListPayload{}, err
	}
	cidrs, err := NormalizeAll(all)
	if err != nil {
		return IPListPayload{}, err
	}
	return IPListPayload{Name: name, Version: ListVersion(cidrs), Generated: m.now().UTC().Format(time.RFC3339), CIDRs: cidrs, Warnings: warn}, nil
}

// compose is the raw union of the providers' last good entries and the manual ones. With override, that provider's
// entries are taken from the argument instead of its state file (used to see what a change would make of a list).
func (m *IPManager) compose(l IPList, override string, entries []string) ([]string, error) {
	var all []string
	for _, p := range l.Providers {
		if p == override {
			all = append(all, entries...)
			continue
		}
		st, err := loadProvider(m.path(p))
		if err != nil {
			return nil, fmt.Errorf("provider %s: %v", p, err)
		}
		if len(st.CIDRs) == 0 {
			return nil, fmt.Errorf("provider %s has not delivered a list yet", p)
		}
		all = append(all, st.CIDRs...)
	}
	return append(all, l.Manual...), nil
}

// --- status ---

// ProviderStatus is one provider in `infra-hub status`.
type ProviderStatus struct {
	LastSuccess *string `json:"last_success"`
	Count       int     `json:"count"`
	LastChange  *string `json:"last_change"`
	LastError   string  `json:"last_error,omitempty"`
	Failures    int     `json:"failures"`
	NextAttempt *string `json:"next_attempt,omitempty"`
	// Held: an update is waiting for `infra-hub iplist accept <provider>`; the old list is still served.
	Held       bool   `json:"held"`
	HeldReason string `json:"held_reason,omitempty"`
	Pending    int    `json:"pending_count,omitempty"`
	// Failing: the state file is unusable, or FailingAfterRuns attempts in a row failed.
	Failing    bool   `json:"failing"`
	StateError string `json:"state_error,omitempty"`
}

// ListStatus is one list in `infra-hub status`.
type ListStatus struct {
	Providers []string `json:"providers"`
	Manual    int      `json:"manual"`
	Hosts     []string `json:"hosts"`
	Entries   int      `json:"entries"` // 0 while a provider has not delivered
	Version   string   `json:"version,omitempty"`
	Warnings  []string `json:"warnings"`
	// History is the last HistoryInStatus entries of the list's change history (`infra-hub iplist history` has all).
	History []HistoryEntry `json:"history"`
}

type IPStatus struct {
	Providers map[string]ProviderStatus `json:"providers"`
	Lists     map[string]ListStatus     `json:"lists"`
}

// Status reads the stored files (not the running process), so `infra-hub status` works while the hub runs.
func (m *IPManager) Status() IPStatus {
	ts := func(t time.Time) *string {
		if t.IsZero() {
			return nil
		}
		v := t.UTC().Format(time.RFC3339)
		return &v
	}
	out := IPStatus{Providers: map[string]ProviderStatus{}, Lists: map[string]ListStatus{}}
	for _, name := range m.used() {
		st, err := loadProvider(m.path(name))
		if err != nil {
			out.Providers[name] = ProviderStatus{Failing: true, StateError: printable(err.Error())}
			continue
		}
		out.Providers[name] = ProviderStatus{LastSuccess: ts(st.LastSuccess), Count: len(st.CIDRs), LastChange: ts(st.LastChange),
			LastError: st.LastError, Failures: st.Failures, NextAttempt: ts(st.NextAttempt), Held: st.Held, HeldReason: st.HeldReason, Pending: len(st.Pending), Failing: st.Failures >= FailingAfterRuns}
	}
	for name, l := range m.Lists {
		hosts := append([]string{}, l.Hosts...)
		sort.Strings(hosts)
		m.mu.Lock()
		warn := m.warnings(l)
		m.mu.Unlock()
		ls := ListStatus{Providers: l.Providers, Manual: len(l.Manual), Hosts: hosts, Warnings: warn,
			History: ReadHistory(m.Dir, name, HistoryInStatus)}
		if p, err := m.Serve(name); err == nil {
			ls.Entries, ls.Version = len(p.CIDRs), p.Version
		}
		out.Lists[name] = ls
	}
	return out
}
