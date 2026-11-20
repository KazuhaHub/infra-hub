package httpsapi

import (
	_ "embed"
	"net/http"
	"strconv"
)

// installScript is the POSIX sh installer served at GET /install. It holds no secret and nothing about this hub: the
// token and the host name are arguments of the caller.
//
//go:embed install.sh
var installScript []byte

func (s *Server) install(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
		return
	}
	if !s.installIP.allow(remoteKey(r.RemoteAddr), s.Now()) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests from this address")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(installScript)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(installScript)
	}
}
