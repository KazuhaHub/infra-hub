package httpsapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/KazuhaHub/infra-hub/internal/state"
)

// Limits of a report. The whole request body is capped at MaxBody as well.
const (
	MaxBody        = 64 << 10
	maxMessage     = 4096
	maxFeatures    = 100
	maxFeatureNote = 1024
)

var (
	commitRe      = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
	featureNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

// validResults are the outcomes of an agent cycle: ok (applied), failed (apply failed), verified (a bundle was fetched
// and verified, nothing applied: verify mode), rejected (a signature, hash or format check failed), unreachable (no hub
// answered) and unchanged (nothing new).
var validResults = map[string]bool{"ok": true, "failed": true, "verified": true, "rejected": true, "unreachable": true, "unchanged": true}

// reportBody is the "report" object of POST /v1/report.
type reportBody struct {
	AppliedCommit string                 `json:"appliedCommit"`
	Result        string                 `json:"result"`
	Message       string                 `json:"message"`
	Time          string                 `json:"time"`
	Features      []state.FeatureSummary `json:"features"`
}

// parseReport decodes and validates a report; unknown fields are an error so that a typo is not silently dropped.
// The returned record has no ReceivedAt yet.
func parseReport(raw json.RawMessage) (state.HostReport, error) {
	var b reportBody
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return state.HostReport{}, fmt.Errorf("report: %w", err)
	}
	// An empty appliedCommit means the agent has not applied anything yet (a host that only verifies, or a first cycle
	// that was rejected or could not reach a hub).
	if b.AppliedCommit != "" && !commitRe.MatchString(b.AppliedCommit) {
		return state.HostReport{}, errors.New("report: appliedCommit must be a full lower-case hex commit id, or empty")
	}
	if !validResults[b.Result] {
		return state.HostReport{}, errors.New(`report: result must be one of "ok", "failed", "verified", "rejected", "unreachable" or "unchanged"`)
	}
	if err := checkText("message", b.Message, maxMessage); err != nil {
		return state.HostReport{}, err
	}
	t, err := time.Parse(time.RFC3339, b.Time)
	if err != nil {
		return state.HostReport{}, errors.New("report: time must be RFC 3339")
	}
	if len(b.Features) > maxFeatures {
		return state.HostReport{}, errors.New("report: too many features")
	}
	seen := map[string]bool{}
	for _, f := range b.Features {
		if !featureNameRe.MatchString(f.Name) {
			return state.HostReport{}, fmt.Errorf("report: feature name %q is not plain", f.Name)
		}
		if seen[f.Name] {
			return state.HostReport{}, fmt.Errorf("report: feature %s twice", f.Name)
		}
		seen[f.Name] = true
		if f.Result != "ok" && f.Result != "failed" && f.Result != "skipped" {
			return state.HostReport{}, fmt.Errorf(`report: feature %s: result must be "ok", "failed" or "skipped"`, f.Name)
		}
		if err := checkText("feature message", f.Message, maxFeatureNote); err != nil {
			return state.HostReport{}, err
		}
	}
	return state.HostReport{AppliedCommit: b.AppliedCommit, Result: b.Result, Message: b.Message,
		Time: t.UTC().Format(time.RFC3339), Features: b.Features}, nil
}

func checkText(what, s string, max int) error {
	if len(s) > max {
		return fmt.Errorf("report: %s is longer than %d bytes", what, max)
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("report: %s is not valid UTF-8", what)
	}
	return nil
}
