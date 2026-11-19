// Package app wires the hub: the subcommands of cmd/infra-hub.
package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/certs"
	"github.com/KazuhaHub/infra-hub/internal/config"
	"github.com/KazuhaHub/infra-hub/internal/gitmirror"
	"github.com/KazuhaHub/infra-hub/internal/iplists"
	"github.com/KazuhaHub/infra-hub/internal/sshserver"
	"github.com/KazuhaHub/infra-hub/internal/state"
)

// Main runs the hub command line (os.Args).
func Main() {
	if len(os.Args) < 2 {
		usage()
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	configPath := fs.String("config", "/etc/infra-hub/config.json", "config file")
	noRefs := fs.Bool("no-refs", false, "status: do not read the git mirror (no git is run)")
	limit := fs.Int("limit", 0, "iplist-history: only the newest N entries")
	// Flags may come before or after the one positional argument: infra-hub iplist-history cloudflare --limit 20
	var pos []string
	for args := os.Args[2:]; ; {
		fs.Parse(args)
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	switch os.Args[1] {
	case "serve":
		log.SetFlags(0) // journald adds the time
		if err := serve(cfg); err != nil {
			log.Fatal(err)
		}
	case "status":
		if err := status(cfg, os.Stdout, *noRefs); err != nil {
			log.Fatal(err)
		}
	case "iplist-history":
		if len(pos) != 1 {
			usage()
		}
		name := pos[0]
		if err := iplists.HistoryReport(cfg.IPListDir, cfg.IPLists, name, *limit, os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "iplist-accept":
		if len(pos) != 1 {
			usage()
		}
		if err := iplists.AcceptReport(cfg.IPListDir, cfg.IPSources, pos[0], os.Stdout); err != nil {
			log.Fatal(err)
		}
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: infra-hub serve|status [-config file] [-no-refs] | infra-hub iplist-accept [-config file] <provider> | infra-hub iplist-history [-config file] <list> [--limit N]")
	os.Exit(2)
}

func serve(cfg config.Config) error {
	keys, err := cfg.ClientKeys()
	if err != nil {
		return err
	}
	signer, err := sshserver.LoadOrCreateHostKey(cfg.HostKey)
	if err != nil {
		return err
	}
	state, err := state.LoadState(cfg.State)
	if err != nil {
		log.Printf("starting with an empty state: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	mirror := &gitmirror.Mirror{Repo: cfg.Repo, Upstream: cfg.Upstream, Interval: time.Duration(cfg.MirrorIntervalSeconds) * time.Second,
		OnSuccess: state.SetMirrorSuccess}
	go mirror.Run(ctx)
	go func() { // throttled state writes
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := state.Flush(); err != nil {
					log.Printf("state: %v", err)
				}
			}
		}
	}()
	defer func() {
		if err := state.Flush(); err != nil {
			log.Printf("state: %v", err)
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
			log.Printf("certificates: not issuing, no Cloudflare token: %v", err)
		} else {
			certMgr.Issuer = &certs.LegoIssuer{Directory: cfg.AcmeDirectory, Email: cfg.AcmeEmail, Dir: filepath.Join(cfg.CertDir, "account"), CFToken: token}
			issuing = true
		}
	}
	if len(cfg.Certs) > 0 {
		if err := certMgr.Store.SetIssuerState(issuing); err != nil {
			log.Printf("certificates: %v", err)
		}
	}

	var ipm *iplists.IPManager
	if len(cfg.IPLists) > 0 {
		ipm = newIPManager(cfg)
		go ipm.Run(ctx) // refreshes the providers and applies accepted changes
	}

	log.Printf("listening on %s, host key %s, %d clients", ln.Addr(), sshserver.SignerFingerprint(signer.PublicKey()), len(keys))
	if issuing {
		go certMgr.Run(ctx) // only once the listener is up
	}
	srv := sshserver.NewServer(sshserver.NewSSHKeyIdentifier(keys), state, signer, cfg.Repo, func(ctx context.Context) (map[string]string, error) {
		return gitmirror.ReadRefs(ctx, cfg.Repo)
	})
	if certMgr != nil {
		srv.Certs = certMgr
	}
	if ipm != nil {
		srv.IPLists = ipm
	}
	maxStale := time.Duration(cfg.MaxStaleSeconds) * time.Second
	srv.Fresh = func() error { return mirror.Fresh(maxStale) }
	return srv.Serve(ctx, ln)
}

// status prints what a monitor reads: the mirror's refs and age, and per host the last time it fetched.
// Mirror age is the time of the last successful fetch from upstream, which the running hub records in the state file.
func status(cfg config.Config, w *os.File, noRefs bool) error {
	st, err := state.LoadState(cfg.State)
	if err != nil {
		return err
	}
	refs := map[string]string{} // -no-refs: a root caller (the hourly mailer) must not run git in the hub user's repository
	if !noRefs {
		refs, _ = gitmirror.ReadRefs(context.Background(), cfg.Repo)
	}
	out := struct {
		Time              string                      `json:"time"`
		Main              string                      `json:"main"`
		MainAttestation   string                      `json:"main_attestation"`
		MirrorLastSuccess *string                     `json:"mirror_last_success"`
		MirrorAge         *int64                      `json:"mirror_age_seconds"`
		Hosts             map[string]state.NodeRecord `json:"hosts"`
		Issuer            string                      `json:"issuer"`
		Certs             map[string]certs.CertStatus `json:"certs"`
		IPLists           *iplists.IPStatus           `json:"iplists,omitempty"`
	}{Issuer: certs.CertStore{Dir: cfg.CertDir}.IssuerState(), Certs: certs.CertStore{Dir: cfg.CertDir}.Status(cfg.Certs), Time: time.Now().UTC().Format(time.RFC3339), Main: refs["refs/heads/main"], MainAttestation: refs["refs/heads/main-attestation"], Hosts: map[string]state.NodeRecord{}}
	if t := st.MirrorSuccess(); !t.IsZero() {
		age := int64(time.Since(t).Seconds())
		out.MirrorAge = &age
		ts := t.Format(time.RFC3339)
		out.MirrorLastSuccess = &ts
	}
	if len(cfg.IPLists) > 0 {
		ips := newIPManager(cfg).Status()
		out.IPLists = &ips
	}
	snap := st.Snapshot()
	for name := range cfg.Clients { // every configured host appears, seen or not
		out.Hosts[name] = snap[name]
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func newIPManager(cfg config.Config) *iplists.IPManager {
	return &iplists.IPManager{Dir: cfg.IPListDir, Sources: cfg.IPSources, Lists: cfg.IPLists}
}
