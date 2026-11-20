package httpsapi

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"filippo.io/age"

	"github.com/KazuhaHub/infra-hub/internal/certs"
)

// notFoundCert is the one answer for every request for a certificate that is not the caller's to ask for: an unknown
// host, an unknown name, a name owned by another host and a host without an age key look the same.
// Every case is logged the same way, at debug level, so neither the log nor the timing tells them apart and an
// unauthenticated peer cannot fill the log.
func notFoundCert(w http.ResponseWriter, host, name, peer string) {
	slog.Debug("cert not found", "host", host, "cert", name, "peer", peer)
	writeError(w, http.StatusNotFound, "not_found", "no such certificate")
}

// cert answers GET /v1/cert/<host>/<name>: the certificate as one JSON line, age-encrypted to the host.
// Anyone may ask (there is no credential); only the owner's age key can read the answer.
func (s *Server) cert(w http.ResponseWriter, r *http.Request, host, name string) {
	now := s.Now()
	peer := remoteKey(r.RemoteAddr)
	if !s.certIP.allow(peer, now) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests from this address")
		return
	}
	rcpt, hasKey := s.Recipients[host]
	if s.Certs == nil || !certs.NameRe.MatchString(name) || !hasKey {
		notFoundCert(w, host, name, peer)
		return
	}
	if owner, ok := s.Certs.Owner(name); !ok || owner != host {
		notFoundCert(w, host, name, peer)
		return
	}
	p, err := s.Certs.Fetch(name)
	if err != nil {
		slog.Warn("cert refused", "host", host, "cert", name, "peer", peer, "err", err)
		writeError(w, http.StatusServiceUnavailable, "not_serving", "the hub cannot serve this certificate now")
		return
	}
	line, err := json.Marshal(p)
	if err != nil {
		slog.Error("cannot encode the certificate", "host", host, "cert", name, "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot prepare the certificate")
		return
	}
	var buf bytes.Buffer
	enc, err := age.Encrypt(&buf, rcpt)
	if err == nil {
		_, err = enc.Write(append(line, '\n'))
	}
	if err == nil {
		err = enc.Close()
	}
	if err != nil {
		slog.Error("cannot encrypt the certificate", "host", host, "cert", name, "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot prepare the certificate")
		return
	}
	slog.Info("cert served", "host", host, "cert", name, "peer", peer, "notAfter", p.NotAfter) // before the answer is sent
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}
