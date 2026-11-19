// Package app is the command line of cmd/infra-hub: the cobra commands and the wiring of the hub's parts.
package app

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/KazuhaHub/infra-hub/internal/config"
	"github.com/KazuhaHub/infra-hub/internal/logx"
	"github.com/KazuhaHub/infra-hub/internal/version"
)

// Exit codes (docs/conventions.md); there are no others.
const (
	ExitOK       = 0
	ExitFailed   = 1 // the operation failed
	ExitUsage    = 2 // bad flag or argument
	ExitNotReady = 3 // not ready, try again
)

const (
	program       = "infra-hub"
	envPrefix     = "INFRA_HUB_"
	defaultConfig = "/etc/infra-hub/config.json"
)

// exitError ends the command with a code. A message is printed to stderr as one line; an empty one prints nothing
// (the command has already written its output).
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

// cli carries what the commands share: the output streams, the clock and what the old spellings switched on.
type cli struct {
	stdout, stderr io.Writer
	now            func() time.Time
	// legacyConfig: the command line used the old `-config` spelling, so `status` keeps printing the old JSON unless
	// a format is asked for. It is what the deployed timer of the private infra repository does today.
	legacyConfig bool
}

// Main runs the hub command line (os.Args[1:]) and returns the process exit code.
func Main(args []string, stdout, stderr io.Writer) int {
	return runCLI(&cli{stdout: stdout, stderr: stderr, now: time.Now}, args)
}

func runCLI(c *cli, args []string) int {
	stdout, stderr := c.stdout, c.stderr
	args, warnings, legacyConfig := rewriteLegacyFlags(args)
	c.legacyConfig = legacyConfig
	for _, w := range warnings {
		fmt.Fprintf(stderr, "%s: warning: %s\n", program, w)
	}
	root := c.newRoot()
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	err := root.Execute()
	if err == nil {
		return ExitOK
	}
	var ee *exitError
	if errors.As(err, &ee) {
		if ee.err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", program, ee.err)
		}
		return ee.code
	}
	fmt.Fprintf(stderr, "%s: %v\n", program, err)
	return ExitFailed
}

func (c *cli) newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   program,
		Short: "The hub: git mirror, certificates and IP lists for a fleet of machines",
		Long: "infra-hub mirrors the configuration repository, issues certificates and collects IP lists for the machines in its config.\n\n" +
			"Every flag can also be set with an environment variable: " + envPrefix + " plus the flag name in upper case with dashes as\nunderscores (--log-level is " + envPrefix + "LOG_LEVEL).",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.String(program),
		Args:          usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return usageErrorf("a command is required (try %s --help)", program)
		},
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if err := applyEnv(cmd.Flags()); err != nil {
				return &exitError{code: ExitUsage, err: err}
			}
			return c.setupLogging(cmd)
		},
	}
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetVersionTemplate("{{.Version}}\n")
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return &exitError{code: ExitUsage, err: err} })
	root.PersistentFlags().String("config", defaultConfig, "path to the hub's config file")
	root.PersistentFlags().String("log-format", "text", "log format on stderr: text or json")
	root.PersistentFlags().String("log-level", "info", "log level: debug, info, warn or error")
	root.AddCommand(c.newServe(), c.newStatus(), c.newIPList(), c.newCA(), c.newHTTPS(), c.newVersion(), c.newLegacyIPListAccept(), c.newLegacyIPListHistory())
	return root
}

// usageArgs makes an argument error a usage error (exit code 2).
func usageArgs(v cobra.PositionalArgs) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if err := v(cmd, args); err != nil {
			return &exitError{code: ExitUsage, err: err}
		}
		return nil
	}
}

// applyEnv fills flags that were not given on the command line from INFRA_HUB_<NAME>.
func applyEnv(fs *pflag.FlagSet) error {
	var err error
	fs.VisitAll(func(f *pflag.Flag) {
		if f.Changed || err != nil || f.Name == "help" || f.Name == "version" {
			return
		}
		name := envPrefix + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		if v, ok := os.LookupEnv(name); ok && v != "" {
			if e := f.Value.Set(v); e != nil {
				err = fmt.Errorf("%s=%q: %w", name, v, e)
				return
			}
		}
	})
	return err
}

// setupLogging installs the slog logger (stderr) as the default logger, and as the ACME library's logger.
func (c *cli) setupLogging(cmd *cobra.Command) error {
	format, _ := cmd.Flags().GetString("log-format")
	level, _ := cmd.Flags().GetString("log-level")
	logger, err := logx.New(c.stderr, format, level)
	if err != nil {
		return &exitError{code: ExitUsage, err: err}
	}
	logx.Install(logger)
	return nil
}

func (c *cli) loadConfig(cmd *cobra.Command) (config.Config, error) {
	path, _ := cmd.Flags().GetString("config")
	cfg, err := config.LoadConfig(path)
	if err != nil {
		return cfg, fmt.Errorf("load config %s: %w", path, err)
	}
	return cfg, nil
}

func (c *cli) newVersion() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  usageArgs(cobra.NoArgs),
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(c.stdout, version.String(program))
		},
	}
}
