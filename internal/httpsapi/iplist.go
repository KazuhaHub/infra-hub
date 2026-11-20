package httpsapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"

	"github.com/KazuhaHub/infra-hub/internal/iplists"
)

// IPListProvider is what GET /v1/iplist/<name> needs; *iplists.IPManager is one.
type IPListProvider interface {
	Has(name string) bool
	Serve(name string) (iplists.IPListPayload, error)
}

var ipListNameRe = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)

// iplist answers GET and HEAD /v1/iplist/<name>: the JSON line that `iplist <name>` sends over SSH. The lists are public
// data (provider ranges and manual entries), so there is no host in the path and nothing is encrypted.
func (s *Server) iplist(w http.ResponseWriter, r *http.Request, name string) {
	peer := remoteKey(r.RemoteAddr)
	if !s.listIP.allow(peer, s.Now()) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests from this address")
		return
	}
	if s.IPLists == nil || !ipListNameRe.MatchString(name) || !s.IPLists.Has(name) {
		writeError(w, http.StatusNotFound, "not_found", "no such list")
		return
	}
	p, err := s.IPLists.Serve(name)
	if err != nil {
		slog.Warn("iplist refused", "list", name, "peer", peer, "err", err)
		writeError(w, http.StatusServiceUnavailable, "not_serving", "the hub cannot serve this list now")
		return
	}
	body, err := json.Marshal(p)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "cannot prepare the list")
		return
	}
	body = append(body, '\n')
	sum := sha256.Sum256(body)
	slog.Info("iplist served", "list", name, "peer", peer, "version", p.Version, "entries", len(p.CIDRs), "warnings", len(p.Warnings))
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	if etagMatches(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}
