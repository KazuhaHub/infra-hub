package httpsapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/atomicfile"
	"github.com/KazuhaHub/infra-hub/internal/hubca"
)

// Identity is where the hub keeps its TLS key and certificate request, and what its certificate must cover.
type Identity struct {
	KeyPath   string   // the hub's TLS key (created on the first start, 0600)
	CSRPath   string   // where the certificate request is written
	CertPath  string   // the signed certificate, placed by the owner's tooling; may be empty or missing
	CAPath    string   // the hub CA certificate
	Addresses []string // IPs and DNS names the certificate must cover
}

// EnsureCSR creates the key if needed and returns the PEM certificate request for Addresses.
func (id Identity) EnsureCSR() ([]byte, error) {
	key, err := LoadOrCreateKey(id.KeyPath)
	if err != nil {
		return nil, err
	}
	return hubca.NewCSR(key, id.Addresses)
}

// Runner serves HTTPS once a valid certificate exists, and keeps looking for one until then.
type Runner struct {
	Identity
	Listen string
	Server *Server
	Now    func() time.Time
	// RetryEvery is how often a missing or invalid certificate is looked at again; ReloadEvery how often a served
	// certificate is reloaded (a renewal needs no restart). Defaults 30 s and 5 min.
	RetryEvery, ReloadEvery time.Duration
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
	if r.ReloadEvery == 0 {
		r.ReloadEvery = 5 * time.Minute
	}
	key, err := LoadOrCreateKey(r.KeyPath)
	if err != nil {
		slog.Error("https is off: cannot load the hub's TLS key", "path", r.KeyPath, "err", err)
		return
	}
	var cert atomic.Pointer[tls.Certificate]
	lastErr := ""
	wroteCSR := false
	for { // wait for a valid certificate
		if !wroteCSR { // a request is on disk whenever there is no usable certificate
			csr, err := hubca.NewCSR(key, r.Addresses)
			if err == nil {
				err = atomicfile.Write(r.CSRPath, csr, 0o644)
			}
			if err != nil {
				slog.Error("cannot write the certificate request", "path", r.CSRPath, "err", err)
			} else {
				wroteCSR = true
				slog.Info("wrote a certificate request; sign it with the hub CA", "path", r.CSRPath)
			}
		}
		c, err := r.load(key)
		if err == nil {
			cert.Store(c)
			break
		}
		if msg := err.Error(); msg != lastErr {
			lastErr = msg
			slog.Error("https is off: no usable hub certificate", "cert", r.CertPath, "csr", r.CSRPath, "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(r.RetryEvery):
		}
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
	slog.Info("https listening", "addr", ln.Addr().String(), "notAfter", cert.Load().Leaf.NotAfter.UTC().Format(time.RFC3339))
	if r.OnListen != nil {
		r.OnListen(ln.Addr())
	}
	go func() {
		t := time.NewTicker(r.ReloadEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if c, err := r.load(key); err != nil {
					if old := cert.Load(); old != nil && !r.Now().Before(old.Leaf.NotAfter) {
						cert.Store(nil) // never keep serving an expired certificate
						slog.Error("the hub certificate expired and has no valid replacement; https handshakes fail", "cert", r.CertPath, "err", err)
					} else {
						slog.Error("keeping the previous hub certificate", "cert", r.CertPath, "err", err)
					}
				} else {
					cert.Store(c)
				}
			}
		}
	}()
	if err := r.Server.Serve(ctx, ln, TLSConfig(cert.Load)); err != nil {
		slog.Error("https stopped", "err", err)
	}
}

func (r *Runner) load(key *ecdsa.PrivateKey) (*tls.Certificate, error) {
	if r.CertPath == "" {
		return nil, errors.New("no hub certificate is configured (https.cert)")
	}
	return LoadServingCert(key, r.CertPath, r.CAPath, r.Addresses, r.Now())
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
