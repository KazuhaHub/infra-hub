package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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

// checkListen refuses a config the hub could not serve with: https is its only listener.
func checkListen(cfg config.Config) error {
	if cfg.HTTPS.Listen == "" {
		return errors.New("https.listen is not set, so the hub would serve nothing")
	}
	return nil
}

// serve runs the hub until ctx ends.
func serve(ctx context.Context, cfg config.Config) error {
	if err := checkListen(cfg); err != nil {
		return err
	}
	key, err := hubkey.Read(cfg.HTTPS.Key)
	var pin string
	if err == nil {
		pin, err = hubkey.Pin(key)
	}
	if err == nil {
		_, err = hubkey.Certificate(key, cfg.HTTPSAddresses, time.Now())
	}
	if err != nil {
		slog.Error("https cannot start: cannot use the hub identity key", "path", cfg.HTTPS.Key, "err", err)
		return fmt.Errorf("https cannot start, so the hub would serve nothing: %w", err)
	}
	slog.Info("starting", "version", version.Version)
	st, err := state.LoadState(cfg.State)
	if err != nil {
		slog.Warn("starting with an empty state", "path", cfg.State, "err", err)
	}

	bundles := &httpsapi.Bundles{Repo: cfg.Repo}
	mirror := &gitmirror.Mirror{Repo: cfg.Repo, Upstream: cfg.Upstream, Interval: time.Duration(cfg.MirrorIntervalSeconds) * time.Second,
		OnSuccess: func(t time.Time) {
			st.SetMirrorSuccess(t)
			bundles.Poke() // wakes the agents that wait for a new bundle
		}}
	bundles.Fresh = func() error { return mirror.Fresh(time.Duration(cfg.MaxStaleSeconds) * time.Second) }
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

	if issuing {
		go certMgr.Run(ctx)
	}
	slog.Info("https identity", "pin", pin)
	hs := httpsapi.NewServer(cfg.AgeRecipients(), st)
	if certMgr != nil {
		hs.Certs = certMgr
	}
	if ipm != nil {
		hs.IPLists = ipm
	}
	hs.Bundles = bundles
	hs.WaitTimeout = time.Duration(cfg.WaitTimeoutSeconds) * time.Second
	run := &httpsapi.Runner{Key: key, Addresses: cfg.HTTPSAddresses, Listen: cfg.HTTPS.Listen, Server: hs}
	httpsDone := make(chan struct{})
	go func() { defer close(httpsDone); run.Run(ctx) }()
	// The hub is its HTTPS server: if that ends before the hub is stopped, the process must not idle.
	<-httpsDone
	if ctx.Err() != nil {
		return nil
	}
	return errors.New("the https server stopped, so the hub serves nothing")
}

// newIssuer is the ACME issuer with the Cloudflare token (a variable so that tests can supply another).
var newIssuer = func(cfg config.Config, token string) certs.Issuer {
	return &certs.LegoIssuer{Directory: cfg.AcmeDirectory, Email: cfg.AcmeEmail, Dir: filepath.Join(cfg.CertDir, "account"), CFToken: token}
}

func newIPManager(cfg config.Config) *iplists.IPManager {
	return &iplists.IPManager{Dir: cfg.IPListDir, Sources: cfg.IPSources, Lists: cfg.IPLists}
}
