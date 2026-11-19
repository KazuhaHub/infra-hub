package app

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/KazuhaHub/infra-hub/internal/certs"
	"github.com/KazuhaHub/infra-hub/internal/config"
	"github.com/KazuhaHub/infra-hub/internal/gitmirror"
	"github.com/KazuhaHub/infra-hub/internal/httpsapi"
	"github.com/KazuhaHub/infra-hub/internal/hubkey"
	"github.com/KazuhaHub/infra-hub/internal/iplists"
	"github.com/KazuhaHub/infra-hub/internal/logx"
	"github.com/KazuhaHub/infra-hub/internal/sshserver"
	"github.com/KazuhaHub/infra-hub/internal/state"
	"github.com/KazuhaHub/infra-hub/internal/version"
)

func (c *cli) newServe() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the hub",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := c.loadConfig(cmd)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return serve(ctx, cfg)
		},
	}
}

// serve runs the hub until ctx ends.
func serve(ctx context.Context, cfg config.Config) error {
	keys, err := cfg.ClientKeys()
	if err != nil {
		return err
	}
	signer, err := sshserver.LoadOrCreateHostKey(cfg.HostKey)
	if err != nil {
		return err
	}
	slog.Info("starting", "version", version.Version)
	st, err := state.LoadState(cfg.State)
	if err != nil {
		slog.Warn("starting with an empty state", "path", cfg.State, "err", err)
	}

	mirror := &gitmirror.Mirror{Repo: cfg.Repo, Upstream: cfg.Upstream, Interval: time.Duration(cfg.MirrorIntervalSeconds) * time.Second,
		OnSuccess: st.SetMirrorSuccess}
	go mirror.Run(ctx)
	go func() { // throttled state writes
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := st.Flush(); err != nil {
					slog.Error("cannot write state", "path", cfg.State, "err", err)
				}
			}
		}
	}()
	defer func() {
		if err := st.Flush(); err != nil {
			slog.Error("cannot write state", "path", cfg.State, "err", err)
		}
	}()

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	var certMgr *certs.CertManager
	issuing := false
	if len(cfg.Certs) > 0 {
		certMgr = &certs.CertManager{Store: certs.CertStore{Dir: cfg.CertDir}, Owners: cfg.Certs}
		tokenPath := cfg.CloudflareTokenFile
		if tokenPath == "" {
			tokenPath = filepath.Join(os.Getenv("CREDENTIALS_DIRECTORY"), "cf_token")
		}
		if token, err := certs.ReadToken(tokenPath); err != nil {
			// Serving what is already stored still works; only issuing and renewing is off.
			slog.Warn("not issuing certificates, no Cloudflare token", "path", tokenPath, "err", err)
		} else {
			logx.AddSecret(token)
			certMgr.Issuer = newIssuer(cfg, token)
			issuing = true
		}
	}
	if len(cfg.Certs) > 0 {
		if err := certMgr.Store.SetIssuerState(issuing); err != nil {
			slog.Error("cannot record the issuer state", "err", err)
		}
	}

	var ipm *iplists.IPManager
	if len(cfg.IPLists) > 0 {
		ipm = newIPManager(cfg)
		go ipm.Run(ctx) // refreshes the providers and applies accepted changes
	}

	slog.Info("listening", "addr", ln.Addr().String(), "hostKey", sshserver.SignerFingerprint(signer.PublicKey()), "clients", len(keys))
	if issuing {
		go certMgr.Run(ctx) // only once the listener is up
	}
	srv := sshserver.NewServer(sshserver.NewSSHKeyIdentifier(keys), st, signer, cfg.Repo, func(ctx context.Context) (map[string]string, error) {
		return gitmirror.ReadRefs(ctx, cfg.Repo)
	})
	if certMgr != nil {
		srv.Certs = certMgr
	}
	if ipm != nil {
		srv.IPLists = ipm
	}
	if cfg.HTTPS.Listen != "" {
		key, err := hubkey.Read(cfg.HTTPS.Key)
		var pin string
		if err == nil {
			pin, err = hubkey.Pin(key)
		}
		if err != nil {
			slog.Error("https is off: cannot use the hub identity key", "path", cfg.HTTPS.Key, "err", err)
		} else {
			slog.Info("https identity", "pin", pin)
			hs := httpsapi.NewServer(cfg.AgeRecipients(), st)
			run := &httpsapi.Runner{Key: key, Addresses: cfg.HTTPSAddresses, Listen: cfg.HTTPS.Listen, Server: hs}
			go run.Run(ctx)
		}
	}
	maxStale := time.Duration(cfg.MaxStaleSeconds) * time.Second
	srv.Fresh = func() error { return mirror.Fresh(maxStale) }
	return srv.Serve(ctx, ln)
}

// newIssuer is the ACME issuer with the Cloudflare token (a variable so that tests can supply another).
var newIssuer = func(cfg config.Config, token string) certs.Issuer {
	return &certs.LegoIssuer{Directory: cfg.AcmeDirectory, Email: cfg.AcmeEmail, Dir: filepath.Join(cfg.CertDir, "account"), CFToken: token}
}

func newIPManager(cfg config.Config) *iplists.IPManager {
	return &iplists.IPManager{Dir: cfg.IPListDir, Sources: cfg.IPSources, Lists: cfg.IPLists}
}
