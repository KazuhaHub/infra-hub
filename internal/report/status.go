// Package report builds the JSON documents the hub prints: `infra-hub status -o json` and `infra-hub iplist history`.
//
// The documents follow docs/conventions.md: apiVersion "v1", lower camelCase names, RFC 3339 UTC times, durations
// as integer seconds with the unit in the name, lists as arrays sorted by name, missing values omitted. The
// previous snake_case status document is still available through Legacy until the machines that parse it have moved.
package report

import (
	"sort"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/certs"
	"github.com/KazuhaHub/infra-hub/internal/iplists"
	"github.com/KazuhaHub/infra-hub/internal/state"
)

// APIVersion is carried by every top-level document.
const APIVersion = "v1"

// StatusInput is what the hub knows when `status` runs; both formats are rendered from it.
type StatusInput struct {
	Now               time.Time
	Main              string
	MainAttestation   string
	MirrorLastSuccess time.Time                   // zero: the mirror has never fetched
	Hosts             []string                    // the configured clients
	Reports           map[string]state.HostReport // the latest agent report per host
	Issuer            string
	Certs             map[string]certs.CertStatus
	IPLists           *iplists.IPStatus
	Bundle            *BundleInput // nil: not examined (status --no-refs)
}

// BundleInput is what the hub would serve at /v1/bundle right now: a commit and time, or the reason it serves none.
type BundleInput struct {
	Commit  string
	Time    time.Time
	Reason  string // no_bundle or stale_mirror, when nothing is served
	Message string
}

// Status is `infra-hub status -o json`.
type Status struct {
	APIVersion        string   `json:"apiVersion"`
	Time              string   `json:"time"`
	Main              string   `json:"main,omitempty"`
	MainAttestation   string   `json:"mainAttestation,omitempty"`
	MirrorLastSuccess string   `json:"mirrorLastSuccess,omitempty"`
	MirrorAgeSeconds  *int64   `json:"mirrorAgeSeconds,omitempty"`
	Hosts             []Host   `json:"hosts"`
	Issuer            string   `json:"issuer"`
	Certs             []Cert   `json:"certs"`
	IPLists           *IPLists `json:"iplists,omitempty"`
	Bundle            *Bundle  `json:"bundle,omitempty"`
}

// Bundle is the config bundle the hub serves: served with its commit and statement time, or not served with the
// error code a host would get and a message for people.
type Bundle struct {
	Served  bool   `json:"served"`
	Commit  string `json:"commit,omitempty"`
	Time    string `json:"time,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

// Host is one configured client. Releases before v0.10.0 also had lastSeen, main and mainAttestation here, fed by the
// SSH server; they are gone (the report's receivedAt is the time the hub last heard from the host).
type Host struct {
	Name string `json:"name"`
	// Report is the latest report the host's agent sent over HTTPS; omitted until it has sent one.
	Report *state.HostReport `json:"report,omitempty"`
}

// Cert is one certificate name of the allow list.
type Cert struct {
	Name        string `json:"name"`
	Owner       string `json:"owner"`
	NotAfter    string `json:"notAfter,omitempty"`
	LastAttempt string `json:"lastAttempt,omitempty"`
	LastResult  string `json:"lastResult,omitempty"`
	LastError   string `json:"lastError,omitempty"`
	Failures    int    `json:"failures"`
	// Failing is what a monitor reads: enough attempts in a row failed. It clears on success.
	Failing     bool   `json:"failing"`
	NextAttempt string `json:"nextAttempt,omitempty"`
}

// IPLists is the IP list section: the providers and the lists built from them.
type IPLists struct {
	Providers []Provider `json:"providers"`
	Lists     []List     `json:"lists"`
}

// Provider is one source of IP ranges.
type Provider struct {
	Name        string `json:"name"`
	LastSuccess string `json:"lastSuccess,omitempty"`
	Count       int    `json:"count"`
	LastChange  string `json:"lastChange,omitempty"`
	LastError   string `json:"lastError,omitempty"`
	Failures    int    `json:"failures"`
	NextAttempt string `json:"nextAttempt,omitempty"`
	// Held: an update waits for `infra-hub iplist accept <provider>`; the old list is still served.
	Held         bool   `json:"held"`
	HeldReason   string `json:"heldReason,omitempty"`
	PendingCount int    `json:"pendingCount,omitempty"`
	Failing      bool   `json:"failing"`
	StateError   string `json:"stateError,omitempty"`
}

// List is one named list.
type List struct {
	Name      string         `json:"name"`
	Providers []string       `json:"providers"`
	Manual    int            `json:"manual"`
	Entries   int            `json:"entries"`
	Version   string         `json:"version,omitempty"`
	Warnings  []string       `json:"warnings"`
	History   []HistoryEntry `json:"history"`
}

// Time formats t as RFC 3339 in UTC; the zero time is "".
func Time(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func strs(s []string) []string {
	out := append([]string{}, s...)
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// NewStatus renders the current document.
func NewStatus(in StatusInput) Status {
	out := Status{APIVersion: APIVersion, Time: Time(in.Now), Main: in.Main, MainAttestation: in.MainAttestation,
		Issuer: in.Issuer, Hosts: []Host{}, Certs: []Cert{}}
	if !in.MirrorLastSuccess.IsZero() {
		age := int64(in.Now.Sub(in.MirrorLastSuccess).Seconds())
		out.MirrorAgeSeconds = &age
		out.MirrorLastSuccess = Time(in.MirrorLastSuccess)
	}
	hosts := append([]string(nil), in.Hosts...)
	sort.Strings(hosts)
	for _, name := range hosts {
		host := Host{Name: name}
		if r, ok := in.Reports[name]; ok {
			r.Features = append([]state.FeatureSummary(nil), r.Features...)
			host.Report = &r
		}
		out.Hosts = append(out.Hosts, host)
	}
	for _, name := range sortedKeys(in.Certs) {
		c := in.Certs[name]
		out.Certs = append(out.Certs, Cert{Name: name, Owner: c.Owner, NotAfter: str(c.NotAfter), LastAttempt: str(c.LastAttempt),
			LastResult: c.LastResult, LastError: c.LastError, Failures: c.Failures, Failing: c.Failing, NextAttempt: str(c.NextAttempt)})
	}
	if b := in.Bundle; b != nil {
		out.Bundle = &Bundle{Served: b.Reason == "", Commit: b.Commit, Time: Time(b.Time), Reason: b.Reason, Message: b.Message}
	}
	if in.IPLists != nil {
		ip := &IPLists{Providers: []Provider{}, Lists: []List{}}
		for _, name := range sortedKeys(in.IPLists.Providers) {
			p := in.IPLists.Providers[name]
			ip.Providers = append(ip.Providers, Provider{Name: name, LastSuccess: str(p.LastSuccess), Count: p.Count, LastChange: str(p.LastChange),
				LastError: p.LastError, Failures: p.Failures, NextAttempt: str(p.NextAttempt), Held: p.Held, HeldReason: p.HeldReason,
				PendingCount: p.Pending, Failing: p.Failing, StateError: p.StateError})
		}
		for _, name := range sortedKeys(in.IPLists.Lists) {
			l := in.IPLists.Lists[name]
			ip.Lists = append(ip.Lists, List{Name: name, Providers: strs(l.Providers), Manual: l.Manual, Entries: l.Entries,
				Version: l.Version, Warnings: strs(l.Warnings), History: NewHistoryEntries(l.History)})
		}
		out.IPLists = ip
	}
	return out
}

// legacyStatus is the snake_case document of releases before apiVersion v1. It is kept byte for byte so that a
// monitor that parses it keeps working; it is selected with `status --format legacy`.
type legacyStatus struct {
	Time              string                      `json:"time"`
	Main              string                      `json:"main"`
	MainAttestation   string                      `json:"main_attestation"`
	MirrorLastSuccess *string                     `json:"mirror_last_success"`
	MirrorAge         *int64                      `json:"mirror_age_seconds"`
	Hosts             map[string]state.NodeRecord `json:"hosts"`
	Issuer            string                      `json:"issuer"`
	Certs             map[string]certs.CertStatus `json:"certs"`
	IPLists           *iplists.IPStatus           `json:"iplists,omitempty"`
}

// Legacy renders the previous document.
func Legacy(in StatusInput) any {
	hosts := map[string]state.NodeRecord{}
	for _, name := range in.Hosts { // last_seen is the time of the host's latest report (the SSH server that fed it is gone)
		var rec state.NodeRecord
		if r, ok := in.Reports[name]; ok {
			rec.LastSeen, _ = time.Parse(time.RFC3339, r.ReceivedAt)
		}
		hosts[name] = rec
	}
	out := legacyStatus{Time: in.Now.UTC().Format(time.RFC3339), Main: in.Main, MainAttestation: in.MainAttestation,
		Hosts: hosts, Issuer: in.Issuer, Certs: in.Certs, IPLists: in.IPLists}
	if out.Certs == nil {
		out.Certs = map[string]certs.CertStatus{}
	}
	if !in.MirrorLastSuccess.IsZero() {
		age := int64(in.Now.Sub(in.MirrorLastSuccess).Seconds())
		ts := in.MirrorLastSuccess.UTC().Format(time.RFC3339)
		out.MirrorAge, out.MirrorLastSuccess = &age, &ts
	}
	return out
}
