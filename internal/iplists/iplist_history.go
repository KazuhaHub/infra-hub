package iplists

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/atomicfile"
)

// Change history of the IP lists: one JSON line per event in <iplist_dir>/history/<list>.jsonl, newest last. It records
// every change of what a list serves (first fetch, provider update, accept) and every held update, with the entries
// added and removed. A monitor can read it later (`infra-hub iplist history`, and the last few entries in `infra-hub status`).

const (
	// HistoryMax is how many entries a list keeps. The file is appended to; when it holds HistoryMax+HistorySlack lines
	// it is rewritten atomically with the newest HistoryMax.
	HistoryMax   = 500
	HistorySlack = 50
	// HistoryInStatus is how many entries `infra-hub status` shows per list.
	HistoryInStatus = 5
	// historyListCap bounds the added and removed lists of one entry (the counts stay exact).
	historyListCap = 1000
)

// HistoryEntry is one line of the history.
type HistoryEntry struct {
	Time string `json:"time"` // RFC 3339, UTC
	// Event is "first fetch", "provider update", "accept" (the served list changed) or "held" (an update was held;
	// the served list did not change).
	Event    string `json:"event"`
	Provider string `json:"provider"`
	// Version is the list's version after the event (for "held": the version still being served, "" if none yet);
	// PreviousVersion the one before it ("" for the first list).
	Version         string   `json:"version"`
	PreviousVersion string   `json:"previous_version"`
	Added           []string `json:"added"`
	Removed         []string `json:"removed"`
	AddedCount      int      `json:"added_count"`
	RemovedCount    int      `json:"removed_count"`
	CountBefore     int      `json:"count_before"`
	CountAfter      int      `json:"count_after"` // for "held": the size of the held list
	Truncated       bool     `json:"truncated,omitempty"`
	Reason          string   `json:"reason,omitempty"` // for "held"
}

func historyPath(dir, list string) string { return filepath.Join(dir, "history", list+".jsonl") }

// AppendHistory adds one entry and keeps the file to the newest HistoryMax entries.
func AppendHistory(dir, list string, e HistoryEntry) error {
	if err := os.MkdirAll(filepath.Join(dir, "history"), 0o700); err != nil {
		return err
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	path := historyPath(dir, list)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := bytes.SplitAfter(data, []byte("\n"))
	if lines[len(lines)-1] == nil || len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	if len(lines) <= HistoryMax+HistorySlack {
		return nil
	}
	return atomicfile.Write(path, bytes.Join(lines[len(lines)-HistoryMax:], nil), 0o600)
}

// ReadHistory returns the newest `limit` entries (all when limit <= 0), oldest first. A line that does not parse is
// skipped: the history is a log for people, never an input to what is served.
func ReadHistory(dir, list string, limit int) []HistoryEntry {
	out := []HistoryEntry{}
	data, err := os.ReadFile(historyPath(dir, list))
	if err != nil {
		return out
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		var e HistoryEntry
		if len(bytes.TrimSpace(line)) == 0 || json.Unmarshal(line, &e) != nil {
			continue
		}
		out = append(out, e)
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

func capList(l []string) ([]string, bool) {
	if l == nil {
		return []string{}, false
	}
	if len(l) > historyListCap {
		return l[:historyListCap], true
	}
	return l, false
}

// listsUsing returns the names of the lists that have provider.
func (m *IPManager) listsUsing(provider string) []string {
	var out []string
	for name, l := range m.Lists {
		if contains(l.Providers, provider) {
			out = append(out, name)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// listNow is what list l serves right now (nil when it cannot be built). Called with m.mu held.
func (m *IPManager) listNow(l IPList, override string, entries []string) []string {
	all, err := m.compose(l, override, entries)
	if err != nil {
		return nil
	}
	cidrs, err := NormalizeAll(all)
	if err != nil {
		return nil
	}
	return cidrs
}

// listsBefore snapshots what each list that uses provider serves, before the provider's state changes.
func (m *IPManager) listsBefore(provider string) map[string][]string {
	out := map[string][]string{}
	for _, name := range m.listsUsing(provider) {
		out[name] = m.listNow(m.Lists[name], "", nil)
	}
	return out
}

func (m *IPManager) appendHistory(list string, e HistoryEntry) {
	e.Time = m.now().UTC().Format(time.RFC3339)
	if err := AppendHistory(m.Dir, list, e); err != nil {
		slog.Error("cannot write the history", "list", list, "err", err)
	}
}

// recordChange writes a history entry for every list whose served entries changed because provider's state changed.
func (m *IPManager) recordChange(provider string, before map[string][]string, cause string, st ProviderState) {
	for name, prev := range before {
		after := m.listNow(m.Lists[name], provider, st.CIDRs)
		if after == nil || (prev != nil && sameStrings(prev, after)) {
			continue
		}
		removed, added := diffEntries(prev, after)
		e := HistoryEntry{Event: cause, Provider: provider, Version: ListVersion(after), AddedCount: len(added), RemovedCount: len(removed),
			CountBefore: len(prev), CountAfter: len(after)}
		if prev != nil {
			e.PreviousVersion = ListVersion(prev)
		}
		var t1, t2 bool
		e.Added, t1 = capList(added)
		e.Removed, t2 = capList(removed)
		e.Truncated = t1 || t2
		m.appendHistory(name, e)
	}
}

// recordHeld writes a "held" entry for every list that uses provider: what the held update would add and remove.
func (m *IPManager) recordHeld(provider string, st ProviderState) {
	for _, name := range m.listsUsing(provider) {
		cur := m.listNow(m.Lists[name], "", nil)
		pend := m.listNow(m.Lists[name], provider, st.Pending)
		if pend == nil {
			continue
		}
		removed, added := diffEntries(cur, pend)
		e := HistoryEntry{Event: "held", Provider: provider, AddedCount: len(added), RemovedCount: len(removed), CountBefore: len(cur),
			CountAfter: len(pend), Reason: printable(st.HeldReason)}
		if cur != nil {
			e.Version, e.PreviousVersion = ListVersion(cur), ListVersion(cur)
		}
		var t1, t2 bool
		e.Added, t1 = capList(added)
		e.Removed, t2 = capList(removed)
		e.Truncated = t1 || t2
		m.appendHistory(name, e)
	}
}

// diffEntries returns what is in a but not in b (removed) and in b but not in a (added).
func diffEntries(a, b []string) (removed, added []string) {
	_, removed, added = diffSets(a, b)
	return
}
