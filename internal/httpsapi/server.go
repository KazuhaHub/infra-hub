package httpsapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/KazuhaHub/infra-hub/internal/certs"
	"github.com/KazuhaHub/infra-hub/internal/logx"
	"github.com/KazuhaHub/infra-hub/internal/state"
	"github.com/KazuhaHub/infra-hub/internal/version"
)

// APIVersion is carried by every document.
const APIVersion = "v1"

// ReportStore keeps the latest report per host.
type ReportStore interface {
	SetReport(host string, r state.HostReport)
	Flush() error
}

// Server answers /v1/healthz, /v1/challenge, /v1/report, /v1/bundle, /v1/cert and /v1/iplist.
type Server struct {
	// Recipients maps a host name to its registered age public key; only these hosts get a challenge.
	Recipients map[string]age.Recipient
	Reports    ReportStore
	Now        func() time.Time
	Rand       io.Reader
	// Bundles serves /v1/bundle/<host>; nil means no bundles.
	Bundles *Bundles
	// Certs serves /v1/cert/<host>/<name>; nil means no certificates.
	Certs certs.CertSource
	// IPLists serves /v1/iplist/<name>; nil means no lists.
	IPLists IPListProvider

	nonces                                                      *nonceStore
	challengeHost, challengeIP, repIP, bundleIP, certIP, listIP *limiter
}

// NewServer returns a server with the default rate limits: a challenge is limited per host (60 a minute, burst 20) and
// per peer address (12 a minute, burst 10: over the 5 minute TTL one address cannot issue enough to push a host's
// real nonce out of its outstanding set); a report per peer address as well.
func NewServer(recipients map[string]age.Recipient, reports ReportStore) *Server {
	return &Server{Recipients: recipients, Reports: reports, Now: time.Now, Rand: rand.Reader, nonces: newNonceStore(),
		challengeHost: newLimiter(60, 20, 4096), challengeIP: newLimiter(12, 10, 16384), repIP: newLimiter(60, 20, 16384),
		bundleIP: newLimiter(30, 20, 16384), certIP: newLimiter(30, 10, 16384), listIP: newLimiter(60, 20, 16384)}
}

type errorBody struct {
	APIVersion string `json:"apiVersion"`
	Error      struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	var b errorBody
	b.APIVersion = APIVersion
	b.Error.Code, b.Error.Message = code, message
	if status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "30")
	}
	writeJSON(w, status, b)
}

// Handler is the /v1 router.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var method string
		var h http.HandlerFunc
		if host, ok := strings.CutPrefix(r.URL.Path, "/v1/bundle/"); ok && host != "" {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
				return
			}
			s.bundle(w, r, host)
			return
		}
		if rest, ok := strings.CutPrefix(r.URL.Path, "/v1/cert/"); ok {
			if r.Method != http.MethodGet {
				w.Header().Set("Allow", "GET")
				writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
				return
			}
			host, name, ok := strings.Cut(rest, "/")
			if !ok || host == "" || name == "" || strings.Contains(name, "/") {
				notFoundCert(w, host, name, remoteKey(r.RemoteAddr))
				return
			}
			s.cert(w, r, host, name)
			return
		}
		if name, ok := strings.CutPrefix(r.URL.Path, "/v1/iplist/"); ok {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET")
				return
			}
			s.iplist(w, r, name)
			return
		}
		switch r.URL.Path {
		case "/v1/healthz":
			method, h = http.MethodGet, s.healthz
		case "/v1/challenge":
			method, h = http.MethodPost, s.challenge
		case "/v1/report":
			method, h = http.MethodPost, s.report
		default:
			writeError(w, http.StatusNotFound, "not_found", "no such path")
			return
		}
		if r.Method != method && !(method == http.MethodGet && r.Method == http.MethodHead) {
			w.Header().Set("Allow", method)
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use "+method)
			return
		}
		h(w, r)
	})
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"apiVersion": APIVersion, "status": "ok", "version": version.Version})
}

// readBody reads at most limit bytes; it answers 413 itself when the body is larger.
func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large", "the request body is too large")
		} else {
			writeError(w, http.StatusBadRequest, "bad_request", "cannot read the request body")
		}
		return nil, false
	}
	return data, true
}

func strictJSON(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

func (s *Server) challenge(w http.ResponseWriter, r *http.Request) {
	now := s.Now()
	peer := remoteKey(r.RemoteAddr)
	if !s.challengeIP.allow(peer, now) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests from this address")
		return
	}
	data, ok := readBody(w, r, 1<<10)
	if !ok {
		return
	}
	var req struct {
		Host string `json:"host"`
	}
	if err := strictJSON(data, &req); err != nil || req.Host == "" {
		writeError(w, http.StatusBadRequest, "bad_request", `the body must be {"host":"<name>"}`)
		return
	}
	rcpt, known := s.Recipients[req.Host]
	if !known {
		writeError(w, http.StatusNotFound, "unknown_host", "no such host")
		return
	}
	if !s.challengeHost.allow(req.Host, now) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many challenges for this host")
		return
	}
	nonce, err := newNonce(s.Rand)
	if err != nil {
		slog.Error("cannot draw a nonce", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot create a challenge")
		return
	}
	logx.AddRecent(nonceHex(nonce))
	ct, err := encryptNonce(rcpt, nonce)
	if err != nil {
		slog.Error("cannot encrypt a challenge", "host", req.Host, "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "cannot create a challenge")
		return
	}
	exp, err := s.nonces.issue(req.Host, nonce, now)
	if err != nil {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many outstanding challenges")
		return
	}
	slog.Debug("challenge issued", "host", req.Host)
	writeJSON(w, http.StatusOK, map[string]string{"apiVersion": APIVersion, "challenge": ct, "expiresAt": exp.UTC().Format(time.RFC3339)})
}

func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	now := s.Now()
	if !s.repIP.allow(remoteKey(r.RemoteAddr), now) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests from this address")
		return
	}
	data, ok := readBody(w, r, MaxBody)
	if !ok {
		return
	}
	var req struct {
		APIVersion string          `json:"apiVersion"`
		Host       string          `json:"host"`
		Nonce      string          `json:"nonce"`
		Report     json.RawMessage `json:"report"`
	}
	if err := strictJSON(data, &req); err != nil || req.APIVersion != APIVersion || req.Host == "" || len(req.Report) == 0 {
		writeError(w, http.StatusBadRequest, "bad_report", `the body must be {"apiVersion":"v1","host":...,"nonce":...,"report":{...}}`)
		return
	}
	// The nonce comes first: nothing about a report is examined for a caller that cannot prove it holds the host's age
	// key. The reason for a refusal is not given (unknown, used, expired and foreign look the same).
	n, valid := parseNonce(req.Nonce)
	if _, known := s.Recipients[req.Host]; !valid || !known || !s.nonces.consume(req.Host, n, now) {
		writeError(w, http.StatusUnauthorized, "bad_nonce", "the nonce is not valid for this host")
		return
	}
	rep, err := parseReport(req.Report)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_report", err.Error())
		return
	}
	rep.ReceivedAt = now.UTC().Format(time.RFC3339)
	s.Reports.SetReport(req.Host, rep)
	if err := s.Reports.Flush(); err != nil {
		slog.Error("cannot write state", "err", err)
	}
	slog.Info("report received", "host", req.Host, "result", rep.Result, "appliedCommit", rep.AppliedCommit)
	writeJSON(w, http.StatusOK, map[string]string{"apiVersion": APIVersion, "status": "ok", "receivedAt": rep.ReceivedAt})
}

// TLSConfig is TLS 1.3 only, with the certificate taken from get on every handshake (so a renewed certificate is used
// without a restart).
func TLSConfig(get func() *tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			if c := get(); c != nil {
				return c, nil
			}
			return nil, errors.New("no certificate")
		},
	}
}

// Serve serves HTTPS on ln until ctx ends.
func (s *Server) Serve(ctx context.Context, ln net.Listener, conf *tls.Config) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		TLSConfig:         conf,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug),
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	err := srv.ServeTLS(ln, "", "")
	<-done
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
