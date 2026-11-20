package agent

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/agenttest"
)

// A hub that says "changed" forever, for the commit whose apply keeps failing, must not make ansible run back to back:
// the retry waits for the normal interval.
func TestKickForTheCommitThatFailedWaitsForTheInterval(t *testing.T) {
	w := agenttest.NewWorld(t)
	p := w.Publish(agenttest.Options{})
	body := bundleBody(t, w)
	url, pin := fakeHubFunc(t, func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/wait/"):
			_, _ = rw.Write([]byte(`{"apiVersion":"v1","changed":true,"commit":"` + p.Commit + `"}`))
		case strings.HasPrefix(r.URL.Path, "/v1/bundle/"):
			rw.Header().Set("Content-Type", "application/octet-stream")
			_, _ = rw.Write(body)
		default:
			http.NotFound(rw, r)
		}
	})
	w.FailStub(true)
	a, _ := newAgentURLs(t, w, ModeApply, []string{url}, []string{pin})
	a.Cfg.Interval = 800 * time.Millisecond
	a.MinCycleGap = 20 * time.Millisecond
	runLoop(t, a)
	time.Sleep(2 * time.Second)
	runs := len(w.StubRuns())
	// cycles at about 0, 0.8 and 1.6 s; without the rule there would be one every 20 ms
	if runs < 1 || runs > 3 {
		t.Errorf("ansible ran %d times in 2 s with an interval of 800 ms", runs)
	}
}
