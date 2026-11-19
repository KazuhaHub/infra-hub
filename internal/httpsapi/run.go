package httpsapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"log/slog"
	"net"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/hubkey"
)

// Runner serves HTTPS with a self-signed certificate that it builds in memory from the hub identity key.
type Runner struct {
	Key       *ecdsa.PrivateKey
	Addresses []string // IPs and DNS names for the certificate's SAN
	Listen    string
	Server    *Server
	Now       func() time.Time
	// RetryEvery is how often a failed listen is tried again (default 30 s).
	RetryEvery time.Duration
	// OnListen is called with the listener's address (tests use it).
	OnListen func(net.Addr)
}

// Run blocks until ctx ends. Every failure is logged and leaves HTTPS off; it never returns an error that would
// stop the rest of the hub.
func (r *Runner) Run(ctx context.Context) {
	if r.Now == nil {
		r.Now = time.Now
	}
	if r.RetryEvery == 0 {
		r.RetryEvery = 30 * time.Second
	}
	cert, err := hubkey.Certificate(r.Key, r.Addresses, r.Now())
	if err != nil {
		slog.Error("https is off: cannot build the hub certificate", "err", err)
		return
	}
	var ln net.Listener
	for {
		if ln, err = net.Listen("tcp", r.Listen); err == nil {
			break
		}
		slog.Error("https is off: cannot listen", "addr", r.Listen, "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(r.RetryEvery):
		}
	}
	slog.Info("https listening", "addr", ln.Addr().String())
	if r.OnListen != nil {
		r.OnListen(ln.Addr())
	}
	if err := r.Server.Serve(ctx, ln, TLSConfig(func() *tls.Certificate { return cert })); err != nil {
		slog.Error("https stopped", "err", err)
	}
}
