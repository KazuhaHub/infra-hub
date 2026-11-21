// Package agentapp is the command line of cmd/infra-agent: the cobra commands around internal/agent.
package agentapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/KazuhaHub/infra-hub/internal/agent"
	"github.com/KazuhaHub/infra-hub/internal/logx"
	"github.com/KazuhaHub/infra-hub/internal/sigstorever"
	"github.com/KazuhaHub/infra-hub/internal/version"
)

// Exit codes (docs/conventions.md); there are no others.
const (
	ExitOK       = 0
	ExitFailed   = 1 // the cycle failed or was rejected
	ExitUsage    = 2 // bad flag, argument or configuration
	ExitNotReady = 3 // not ready, try again: no hub was reachable, or another agent holds the lock
)

const program = "infra-agent"

type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("exit status %d", e.code)
	}
	return e.err.Error()
}
func (e *exitError) Unwrap() error { return e.err }

func usageErrorf(format string, a ...any) error {
	return &exitError{code: ExitUsage, err: fmt.Errorf(format, a...)}
}

type cli struct {
	stdout, stderr io.Writer
	environ        func(string) (string, bool)
}

// Main runs the agent's command line (os.Args[1:]) and returns the process exit code.
func Main(args []string, stdout, stderr io.Writer) int {
	return runCLI(&cli{stdout: stdout, stderr: stderr, environ: os.LookupEnv}, args)
}

func runCLI(c *cli, args []string) int {
	root := c.newRoot()
	root.SetArgs(args)
	root.SetOut(c.stdout)
	root.SetErr(c.stderr)
	err := root.Execute()
	if err == nil {
		return ExitOK
	}
	var ee *exitError
	if errors.As(err, &ee) {
		if ee.err != nil {
			fmt.Fprintf(c.stderr, "%s: %v\n", program, ee.err)
		}
		return ee.code
	}
	var ce *agent.ConfigError
	if errors.As(err, &ce) {
		fmt.Fprintf(c.stderr, "%s: %v\n", program, err)
		return ExitUsage
	}
	fmt.Fprintf(c.stderr, "%s: %v\n", program, err)
	return ExitFailed
}

func (c *cli) newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   program,
		Short: "The per-machine agent: fetch the config bundle, verify it, apply it, report",
		Long: "infra-agent fetches this host's signed config bundle from the hubs over HTTPS (trusting only the pinned hub key),\n" +
			"verifies it, applies it with ansible and reports the result. It only connects outward and opens no port.\n\n" +
			"Settings are KEY=VALUE lines in the env file (default " + agent.DefaultEnvFile + "); see docs/agent.md. Every flag can also\n" +
			"be set with an environment variable: " + agent.EnvPrefix + " plus the flag name in upper case with dashes as underscores.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.String(program),
		Args:          usageArgs(cobra.NoArgs),
		RunE: func(*cobra.Command, []string) error {
			return usageErrorf("a command is required (try %s --help)", program)
		},
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if err := c.applyEnv(cmd.Flags()); err != nil {
				return &exitError{code: ExitUsage, err: err}
			}
			return c.setupLogging(cmd)
		},
	}
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetVersionTemplate("{{.Version}}\n")
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return &exitError{code: ExitUsage, err: err} })
	pf := root.PersistentFlags()
	pf.String("env-file", agent.DefaultEnvFile, "path to agent.env")
	pf.String("log-format", "text", "log format on stderr: text or json")
	pf.String("log-level", "info", "log level: debug, info, warn or error")
	pf.String("repo", agent.DefaultRepo, "repository the bundle statement must name (for tests)")
	pf.String("ansible", "ansible-playbook", "ansible-playbook program (for tests)")
	pf.String("ssh-keygen", "ssh-keygen", "ssh-keygen program (for tests)")
	pf.String("infra-lock", agent.DefaultInfraLock, "infra-pull's lock file (for tests)")
	pf.String("infra-applied", agent.DefaultInfraApplied, "infra-pull's applied record (for tests)")
	for _, n := range hiddenFlags {
		_ = pf.MarkHidden(n)
	}
	root.AddCommand(c.newRun(), c.newStatus(), c.newCheckConfig(), c.newCert(), c.newVersion())
	return root
}

func usageArgs(v cobra.PositionalArgs) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if err := v(cmd, args); err != nil {
			return &exitError{code: ExitUsage, err: err}
		}
		return nil
	}
}

// hiddenFlags are for tests only: they can be set on the command line but never from the environment or agent.env, so
// nothing a service manager or a file hands over can redirect the agent to another repository or another program.
var hiddenFlags = []string{"repo", "ansible", "ssh-keygen", "infra-lock", "infra-applied"}

// applyEnv fills flags that were not given on the command line from INFRA_AGENT_<NAME>.
func (c *cli) applyEnv(fs *pflag.FlagSet) error {
	var err error
	fs.VisitAll(func(f *pflag.Flag) {
		if f.Changed || err != nil || f.Name == "help" || f.Name == "version" || contains(hiddenFlags, f.Name) {
			return
		}
		name := agent.EnvPrefix + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		if v, ok := c.environ(name); ok && v != "" {
			if e := f.Value.Set(v); e != nil {
				err = fmt.Errorf("%s=%q: %w", name, v, e)
				return
			}
			f.Changed = true
		}
	})
	return err
}

// setupLogging installs the slog logger. A log format or level that the flag and the environment leave alone may come
// from the env file, so that one file configures the service.
func (c *cli) setupLogging(cmd *cobra.Command) error {
	format, _ := cmd.Flags().GetString("log-format")
	level, _ := cmd.Flags().GetString("log-level")
	if path, _ := cmd.Flags().GetString("env-file"); path != "" {
		if data, err := os.ReadFile(path); err == nil {
			if vals, err := agent.ParseEnvFile(data); err == nil {
				if v := vals[agent.EnvPrefix+"LOG_FORMAT"]; v != "" && !cmd.Flags().Changed("log-format") {
					format = v
				}
				if v := vals[agent.EnvPrefix+"LOG_LEVEL"]; v != "" && !cmd.Flags().Changed("log-level") {
					level = v
				}
			}
		}
	}
	logger, err := logx.New(c.stderr, format, level)
	if err != nil {
		return &exitError{code: ExitUsage, err: err}
	}
	logx.Install(logger)
	return nil
}

func (c *cli) loadConfig(cmd *cobra.Command) (agent.Config, error) {
	path, _ := cmd.Flags().GetString("env-file")
	cfg, err := agent.LoadConfig(path, c.environ)
	if err != nil {
		return cfg, err
	}
	cfg.Repo, _ = cmd.Flags().GetString("repo")
	return cfg, nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func (c *cli) newVersion() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  usageArgs(cobra.NoArgs),
		Run:   func(*cobra.Command, []string) { fmt.Fprintln(c.stdout, version.String(program)) },
	}
}

func (c *cli) newRun() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Fetch, verify, apply and report: once, or forever",
		Long: "run repeats the cycle every INFRA_AGENT_INTERVAL (default 5m, each wait with 10 % jitter) until it is stopped.\n" +
			"With --once it runs one cycle and exits: 0 when the result is ok, verified or unchanged; 1 when it is failed or rejected,\n" +
			"3 when no hub was reachable, another infra-agent holds the lock in the state directory, or the run was interrupted by a signal; 2 for a configuration error.\n\n" +
			"In verify mode (the default) the bundle is fetched, decrypted, verified and extracted but ansible never runs; in apply\n" +
			"mode it is applied as well.",
		Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := c.loadConfig(cmd)
			if err != nil {
				return err
			}
			id, err := cfg.CheckFiles()
			if err != nil {
				return err
			}
			lock, err := agent.AcquireLock(cfg.StateDir)
			if err != nil {
				if errors.Is(err, agent.ErrLocked) {
					return &exitError{code: ExitNotReady, err: err}
				}
				return err
			}
			defer lock.Close()
			a, err := agent.New(cfg, id)
			if err != nil {
				return err
			}
			if cfg.WantsSigstore() {
				a.SigstoreTUF = sigstoreManager(cfg)
			}
			a.Ansible, _ = cmd.Flags().GetString("ansible")
			a.SSHKeygen, _ = cmd.Flags().GetString("ssh-keygen")
			a.InfraLock, _ = cmd.Flags().GetString("infra-lock")
			a.InfraApplied, _ = cmd.Flags().GetString("infra-applied")
			for _, n := range hiddenFlags {
				if f := cmd.Flags().Lookup(n); f != nil && f.Value.String() != f.DefValue {
					slog.Warn("a test-only flag is set", "flag", "--"+n, "value", f.Value.String())
				}
			}
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			if once, _ := cmd.Flags().GetBool("once"); once {
				o, err := a.Cycle(ctx)
				if _, serr := os.Lstat(agent.RestartFile(cfg.StateDir)); serr == nil {
					slog.Warn("the configuration run asked for a restart of the agent; run --once does not restart, restart infra-agent.service",
						"file", agent.RestartFile(cfg.StateDir))
				}
				if errors.Is(err, agent.ErrInterrupted) {
					return &exitError{code: ExitNotReady, err: err}
				}
				if err != nil {
					return err
				}
				return resultError(o)
			}
			versionInfo := version.Version
			a.Out = c.stderr
			startupLog(cfg, versionInfo)
			// Loop also returns on a restart request: exit 0, and systemd (Restart=always) starts the agent again.
			a.Loop(ctx)
			return nil
		},
	}
	cmd.Flags().Bool("once", false, "run one cycle and exit")
	return cmd
}

func startupLog(cfg agent.Config, v string) {
	slog.Info("infra-agent started", "version", v, "host", cfg.Host, "mode", cfg.Mode, "interval", cfg.Interval.String(), "hubs", len(cfg.Token.Hubs), "githubFallback", cfg.GitHubRepo != "")
}

// resultError is the exit status of a --once cycle.
func resultError(o agent.Outcome) error {
	switch o.Result {
	case agent.ResultOK, agent.ResultVerified, agent.ResultUnchanged:
		return nil
	case agent.ResultUnreachable:
		return &exitError{code: ExitNotReady, err: fmt.Errorf("%s: %s", o.Result, o.Message)}
	}
	return &exitError{code: ExitFailed, err: fmt.Errorf("%s: %s", o.Result, o.Message)}
}

type statusDoc struct {
	APIVersion string `json:"apiVersion"`
	Host       string `json:"host"`
	Mode       string `json:"mode"`
	// SigstoreRoot is where the Sigstore trusted root came from (signature modes either and sigstore, once a bundle was verified).
	SigstoreRoot *sigstorever.Info `json:"sigstoreRoot,omitempty"`
	agent.State
}

func (c *cli) newStatus() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show what the agent applied, verified and did last",
		Long:  "Reads the state directory: the applied and the verified bundle (commit and statement time), the last cycle's result, the hub that served it and when it ran.",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			output, _ := cmd.Flags().GetString("output")
			if output != "table" && output != "json" {
				return usageErrorf("--output %q: want table or json", output)
			}
			cfg, err := c.loadConfig(cmd)
			if err != nil {
				return err
			}
			st, err := agent.LoadState(cfg.StateDir)
			if err != nil {
				return err
			}
			doc := statusDoc{APIVersion: "v1", Host: cfg.Host, Mode: cfg.Mode, State: st}
			if cfg.WantsSigstore() {
				if info, err := sigstorever.ReadInfo(cfg.SigstoreInfoPath()); err == nil {
					doc.SigstoreRoot = &info
				}
			}
			if output == "json" {
				enc := json.NewEncoder(c.stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(doc)
			}
			tw := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
			row := func(k, v string) { fmt.Fprintf(tw, "%s\t%s\n", k, orDash(v)) }
			row("host", cfg.Host)
			row("mode", cfg.Mode)
			row("applied", recordText(st.Applied, "appliedAt"))
			row("verified", recordText(st.Verified, "verifiedAt"))
			if cfg.WantsSigstore() {
				if info, err := sigstorever.ReadInfo(cfg.SigstoreInfoPath()); err == nil {
					row("sigstore root", rootInfoText(info))
				} else {
					row("sigstore root", "")
				}
			}
			row("last result", st.LastResult)
			row("last message", st.LastMessage)
			if st.LastHub == agent.GitHubSource {
				row("last hub", "GitHub fallback (no hub gave a bundle)")
			} else {
				row("last hub", st.LastHub)
			}
			if st.LastCycle != nil {
				row("last cycle", st.LastCycle.UTC().Format(time.RFC3339))
			} else {
				row("last cycle", "")
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringP("output", "o", "table", "output format: table or json")
	return cmd
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func recordText(r *agent.Record, atLabel string) string {
	if r == nil {
		return ""
	}
	text := fmt.Sprintf("%s (statement %s, %s %s)", r.Commit, r.Time.UTC().Format(time.RFC3339), atLabel, r.At.UTC().Format(time.RFC3339))
	if r.Signature != "" {
		text += ", signature " + r.Signature
	}
	return text
}

func (c *cli) newCheckConfig() *cobra.Command {
	return &cobra.Command{
		Use:   "check-config",
		Short: "Validate agent.env, the token and the key files, and ask each hub for /v1/healthz",
		Long: "Validates the settings, reads the age key and the allowed_signers file (not needed in signature mode sigstore), prints the\n" +
			"signature mode and whether the embedded Sigstore trusted root parses, and calls GET /v1/healthz on each hub with the\n" +
			"pin, printing what it found. Exit code 0 when the configuration is valid and at least one hub answers, 1 when no hub\n" +
			"answers, 2 when the configuration is not valid.",
		Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := c.loadConfig(cmd)
			if err != nil {
				return err
			}
			id, err := cfg.CheckFiles()
			if err != nil {
				return err
			}
			w := c.stdout
			fmt.Fprintf(w, "host:      %s\nmode:      %s\ninterval:  %s\nstate dir: %s\nage key:   %s (recipient %s)\nsigners:   %s\npins:      %d\n",
				cfg.Host, cfg.Mode, cfg.Interval, cfg.StateDir, cfg.AgeKey, strings.Join(id.Recipients(), ","), cfg.Signers, len(cfg.Token.Pins))
			fmt.Fprintf(w, "signature: %s\n", cfg.Signature)
			summary, rootErr := sigstorever.RootSummary()
			switch {
			case rootErr != nil && cfg.WantsSigstore():
				return &agent.ConfigError{Err: rootErr}
			case rootErr != nil:
				fmt.Fprintf(w, "sigstore:  not used; embedded trusted root does not parse: %v\n", rootErr)
			case !cfg.WantsSigstore():
				fmt.Fprintf(w, "sigstore:  not used; embedded trusted root ok (%s)\n", summary)
			default:
				fmt.Fprintf(w, "sigstore:  embedded trusted root ok (%s); identity %s, repo ID %s, owner ID %s\n", summary, sigstorever.Identity(cfg.Repo), cfg.SigstoreRepoID, cfg.SigstoreOwnerID)
				ctx, cancel := context.WithTimeout(cmd.Context(), sigstorever.FetchTimeout+5*time.Second)
				_, info, err := sigstoreManager(cfg).Root(ctx)
				cancel()
				if err != nil {
					return &agent.ConfigError{Err: err}
				}
				fmt.Fprintf(w, "sigstore root: %s\n", rootInfoText(info))
			}
			if cfg.GitHubRepo == "" {
				fmt.Fprintln(w, "github fallback: off")
			} else {
				if err := cfg.CheckGitHubFiles(); err != nil {
					return err
				}
				if cfg.GitHubAppID != "" {
					fmt.Fprintf(w, "github fallback: on (repo %s, GitHub App %s, key %s)\n", cfg.GitHubRepo, cfg.GitHubAppID, cfg.GitHubAppKey)
				} else {
					fmt.Fprintf(w, "github fallback: on (repo %s, key %s, known_hosts %s)\n", cfg.GitHubRepo, cfg.GitHubKey, cfg.GitHubKnownHosts)
				}
			}
			healthy := 0
			for _, u := range cfg.Token.Hubs {
				h, err := agent.NewHub(u, cfg.Token.Pins)
				if err != nil {
					return err
				}
				ctx, cancel := context.WithTimeout(cmd.Context(), agent.HTTPTimeout)
				start := time.Now()
				status, err := h.Health(ctx)
				cancel()
				took := time.Since(start).Round(time.Millisecond)
				if err != nil {
					fmt.Fprintf(w, "hub %s: %v (%s)\n", hostPort(u), err, took)
					continue
				}
				healthy++
				fmt.Fprintf(w, "hub %s: pin matched, status %s (%s)\n", hostPort(u), status, took)
			}
			if healthy == 0 {
				return &exitError{code: ExitFailed, err: errors.New("no hub answered")}
			}
			return nil
		},
	}
}

// sigstoreManager is the TUF-backed trusted root of a configuration (a variable so that tests stay off the network).
var sigstoreManager = func(cfg agent.Config) *sigstorever.Manager { return cfg.SigstoreManager() }

// rootInfoText says where the trusted root came from and how old that is.
func rootInfoText(i sigstorever.Info) string {
	if i.Updated.IsZero() {
		return i.Source
	}
	return fmt.Sprintf("%s, TUF metadata refreshed %s (%s ago)", i.Source, i.Updated.UTC().Format(time.RFC3339), time.Since(i.Updated).Round(time.Minute))
}

func hostPort(u string) string {
	if p, err := url.Parse(u); err == nil {
		return p.Host
	}
	return u
}
