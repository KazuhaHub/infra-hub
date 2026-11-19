package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/KazuhaHub/infra-hub/internal/certs"
	"github.com/KazuhaHub/infra-hub/internal/config"
	"github.com/KazuhaHub/infra-hub/internal/gitmirror"
	"github.com/KazuhaHub/infra-hub/internal/report"
	"github.com/KazuhaHub/infra-hub/internal/state"
)

func (c *cli) newStatus() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the mirror, the hosts, the certificates and the IP lists",
		Long: "Show what a monitor reads: the mirror's refs and age, per host the last time it fetched, the certificates and the IP lists.\n\n" +
			"Exit code 3 means the hub is not ready yet: its mirror has never fetched successfully.",
		Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := c.loadConfig(cmd)
			if err != nil {
				return err
			}
			noRefs, _ := cmd.Flags().GetBool("no-refs")
			output, _ := cmd.Flags().GetString("output")
			format, _ := cmd.Flags().GetString("format")
			legacy := format == "legacy" || (c.legacyConfig && !cmd.Flags().Changed("format") && !cmd.Flags().Changed("output"))
			if format != "" && format != "legacy" {
				return usageErrorf("--format %q: only \"legacy\" is known", format)
			}
			if output != "table" && output != "json" {
				return usageErrorf("--output %q: want table or json", output)
			}
			in, err := collectStatus(cmd.Context(), cfg, noRefs, c.now())
			if err != nil {
				return err
			}
			if legacy {
				// The old document is always JSON and never "not ready": the deployed monitor reads it as before.
				return writeJSON(c.stdout, report.Legacy(in))
			}
			doc := report.NewStatus(in)
			if output == "json" {
				err = writeJSON(c.stdout, doc)
			} else {
				err = writeStatusTable(c.stdout, doc)
			}
			if err != nil {
				return err
			}
			if in.MirrorLastSuccess.IsZero() {
				return &exitError{code: ExitNotReady}
			}
			return nil
		},
	}
	cmd.Flags().StringP("output", "o", "table", "output format: table or json")
	cmd.Flags().Bool("no-refs", false, "do not read the git mirror (no git is run)")
	cmd.Flags().String("format", "", "")
	_ = cmd.Flags().MarkHidden("format")
	return cmd
}

// collectStatus reads what `status` shows. Mirror age is the time of the last successful fetch from upstream, which
// the running hub records in the state file.
func collectStatus(ctx context.Context, cfg config.Config, noRefs bool, now time.Time) (report.StatusInput, error) {
	st, err := state.LoadState(cfg.State)
	if err != nil {
		return report.StatusInput{}, err
	}
	refs := map[string]string{} // --no-refs: a root caller (the hourly mailer) must not run git in the hub user's repository
	if !noRefs {
		if ctx == nil {
			ctx = context.Background()
		}
		refs, _ = gitmirror.ReadRefs(ctx, cfg.Repo)
	}
	store := certs.CertStore{Dir: cfg.CertDir}
	in := report.StatusInput{Now: now.UTC(), Main: refs["refs/heads/main"], MainAttestation: refs["refs/heads/main-attestation"],
		MirrorLastSuccess: st.MirrorSuccess(), Hosts: map[string]state.NodeRecord{}, Issuer: store.IssuerState(), Certs: store.Status(cfg.Certs)}
	if len(cfg.IPLists) > 0 {
		ips := newIPManager(cfg).Status()
		in.IPLists = &ips
	}
	snap := st.Snapshot()
	for name := range cfg.Clients { // every configured host appears, seen or not
		in.Hosts[name] = snap[name]
	}
	return in, nil
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func short12(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return orDash(s)
}

// writeStatusTable prints the short human form of the status document.
func writeStatusTable(w io.Writer, s report.Status) error {
	fmt.Fprintf(w, "time:     %s\n", s.Time)
	mirror := "never fetched"
	if s.MirrorLastSuccess != "" {
		mirror = fmt.Sprintf("%s (%ds ago)", s.MirrorLastSuccess, *s.MirrorAgeSeconds)
	}
	fmt.Fprintf(w, "mirror:   %s\n", mirror)
	fmt.Fprintf(w, "main:     %s\nattested: %s\nissuer:   %s\n", short12(s.Main), short12(s.MainAttestation), s.Issuer)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "\nHOST\tLAST SEEN\tMAIN")
	for _, h := range s.Hosts {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", h.Name, orDash(h.LastSeen), short12(h.Main))
	}
	if len(s.Certs) > 0 {
		fmt.Fprintln(tw, "\nCERT\tOWNER\tNOT AFTER\tRESULT\tFAILING")
		for _, c := range s.Certs {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%t\n", c.Name, c.Owner, orDash(c.NotAfter), orDash(c.LastResult), c.Failing)
		}
	}
	if s.IPLists != nil {
		fmt.Fprintln(tw, "\nPROVIDER\tLAST SUCCESS\tENTRIES\tHELD\tFAILING")
		for _, p := range s.IPLists.Providers {
			fmt.Fprintf(tw, "%s\t%s\t%d\t%t\t%t\n", p.Name, orDash(p.LastSuccess), p.Count, p.Held, p.Failing)
		}
		fmt.Fprintln(tw, "\nLIST\tENTRIES\tHOSTS\tWARNINGS")
		for _, l := range s.IPLists.Lists {
			fmt.Fprintf(tw, "%s\t%d\t%d\t%d\n", l.Name, l.Entries, len(l.Hosts), len(l.Warnings))
		}
	}
	return tw.Flush()
}
