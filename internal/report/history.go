package report

import "github.com/KazuhaHub/infra-hub/internal/iplists"

// HistoryEntry is one change of a list (see iplists.HistoryEntry for the stored form).
type HistoryEntry struct {
	Time            string   `json:"time"`
	Event           string   `json:"event"`
	Provider        string   `json:"provider"`
	Version         string   `json:"version"`
	PreviousVersion string   `json:"previousVersion"`
	Added           []string `json:"added"`
	Removed         []string `json:"removed"`
	AddedCount      int      `json:"addedCount"`
	RemovedCount    int      `json:"removedCount"`
	CountBefore     int      `json:"countBefore"`
	CountAfter      int      `json:"countAfter"`
	Truncated       bool     `json:"truncated,omitempty"`
	Reason          string   `json:"reason,omitempty"`
}

// History is `infra-hub iplist history <list>`: the entries, newest last.
type History struct {
	APIVersion string         `json:"apiVersion"`
	List       string         `json:"list"`
	Entries    []HistoryEntry `json:"entries"`
}

// NewHistoryEntries converts stored entries; the result is never nil.
func NewHistoryEntries(in []iplists.HistoryEntry) []HistoryEntry {
	out := make([]HistoryEntry, 0, len(in))
	for _, e := range in {
		out = append(out, HistoryEntry{Time: e.Time, Event: e.Event, Provider: e.Provider, Version: e.Version, PreviousVersion: e.PreviousVersion,
			Added: strs(e.Added), Removed: strs(e.Removed), AddedCount: e.AddedCount, RemovedCount: e.RemovedCount, CountBefore: e.CountBefore,
			CountAfter: e.CountAfter, Truncated: e.Truncated, Reason: e.Reason})
	}
	return out
}

// NewHistory builds the document for one list.
func NewHistory(list string, entries []iplists.HistoryEntry) History {
	return History{APIVersion: APIVersion, List: list, Entries: NewHistoryEntries(entries)}
}
