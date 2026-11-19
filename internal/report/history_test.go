package report

import (
	"testing"

	"github.com/KazuhaHub/infra-hub/internal/iplists"
)

func TestHistoryGolden(t *testing.T) {
	entries := []iplists.HistoryEntry{
		{Time: "2026-11-01T00:00:00Z", Event: "first fetch", Provider: "cloudflare", Version: "aaaa", Added: []string{"192.0.2.0/24"}, Removed: []string{}, AddedCount: 1, CountAfter: 1},
		{Time: "2026-11-19T08:10:00Z", Event: "held", Provider: "cloudflare", Version: "aaaa", PreviousVersion: "aaaa", Added: []string{}, Removed: []string{"192.0.2.0/24"},
			RemovedCount: 1, CountBefore: 1, Reason: "shrank by 100%"},
	}
	golden(t, "history-v1.json", NewHistory("edge", entries))
	golden(t, "history-empty-v1.json", NewHistory("edge", nil))
}
