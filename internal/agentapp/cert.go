package agentapp

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/KazuhaHub/infra-hub/internal/agent"
	"github.com/KazuhaHub/infra-hub/internal/certs"
)

func (c *cli) newCert() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cert <name> [--hub URL] [--out-dir DIR]",
		Short: "Fetch a certificate from the hubs and decrypt it",
		Long: "cert asks the hubs of the token, in order, for GET /v1/cert/<host>/<name>, decrypts the answer with this host's age key and\n" +
			"checks that it is a JSON object with name, fullchain, privkey and not_after.\n\n" +
			"Without --out-dir the first decrypted answer is printed on stdout (one JSON line) and errors go to stderr. With --out-dir\n" +
			"every hub is asked and, for the hub at position i of the token (0-based), DIR/<i>.json holds its decrypted answer or\n" +
			"DIR/<i>.err a one-line reason; the files are 0600, owned by the directory's owner, and nothing in DIR is followed if\n" +
			"it is a symlink. --hub restricts the request to one hub of the token.\n\n" +
			"Exit code 0 when at least one hub answered, 1 when none did, 2 for a configuration or usage error.",
		Args: usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if !certs.NameRe.MatchString(name) {
				return usageErrorf("%q is not a certificate name (a lower-case DNS name)", name)
			}
			only, _ := cmd.Flags().GetString("hub")
			outDir, _ := cmd.Flags().GetString("out-dir")
			cfg, err := c.loadConfig(cmd)
			if err != nil {
				return err
			}
			var idx []int
			for i, u := range cfg.Token.Hubs {
				if only == "" || u == only {
					idx = append(idx, i)
				}
			}
			if len(idx) == 0 {
				return usageErrorf("--hub %q is not one of the hubs of the token (%s)", only, strings.Join(cfg.Token.Hubs, ", "))
			}
			id, err := agent.LoadIdentity(cfg.AgeKey)
			if err != nil {
				return &agent.ConfigError{Err: err}
			}
			var dir *agent.CertOutDir
			if outDir != "" {
				if dir, err = agent.OpenCertOutDir(outDir); err != nil {
					return usageErrorf("--out-dir: %v", err)
				}
				defer dir.Close()
				for _, i := range idx {
					if err := dir.Clear(i); err != nil {
						return usageErrorf("--out-dir: %v", err)
					}
				}
			}
			answered := 0
			for _, i := range idx {
				reply, err := c.fetchCert(cmd.Context(), cfg, i, name, id)
				if dir == nil {
					if err != nil {
						fmt.Fprintf(c.stderr, "%s: hub %s: %s\n", program, hostPort(cfg.Token.Hubs[i]), oneLine(err.Error()))
						continue
					}
					if _, werr := c.stdout.Write(reply); werr != nil {
						return werr
					}
					return nil
				}
				if err != nil {
					fmt.Fprintf(c.stderr, "%s: hub %s: %s\n", program, hostPort(cfg.Token.Hubs[i]), oneLine(err.Error()))
					if werr := dir.Write(i, false, []byte(oneLine(err.Error())+"\n")); werr != nil {
						return fmt.Errorf("write %d.err: %w", i, werr)
					}
					continue
				}
				if werr := dir.Write(i, true, reply); werr != nil {
					return fmt.Errorf("write %d.json: %w", i, werr)
				}
				answered++
			}
			if dir != nil && answered > 0 {
				return nil
			}
			return &exitError{code: ExitFailed, err: errors.New("no hub gave the certificate")}
		},
	}
	cmd.Flags().String("hub", "", "ask only this hub (one of the hubs of the token)")
	cmd.Flags().String("out-dir", "", "write <i>.json or <i>.err per hub into this directory instead of printing")
	return cmd
}

func (c *cli) fetchCert(ctx context.Context, cfg agent.Config, i int, name string, id *agent.Identity) ([]byte, error) {
	h, err := agent.NewHub(cfg.Token.Hubs[i], cfg.Token.Pins)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, agent.HTTPTimeout)
	defer cancel()
	return h.Cert(ctx, cfg.Host, name, id)
}

// oneLine makes a message fit on one line of an .err file.
func oneLine(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > 300 {
		s = s[:300]
	}
	return strings.TrimSpace(s)
}
