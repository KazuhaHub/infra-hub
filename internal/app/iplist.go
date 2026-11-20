package app

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/KazuhaHub/infra-hub/internal/iplists"
	"github.com/KazuhaHub/infra-hub/internal/report"
)

func (c *cli) newIPList() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "iplist",
		Short: "Work with the IP lists",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return usageErrorf("iplist needs a command: accept or history")
		},
	}
	accept := &cobra.Command{
		Use:   "accept <provider>",
		Short: "Apply a held IP list update",
		Long:  "Record that a person has reviewed the held update of a provider. The running hub applies it within a minute.",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE:  c.runAccept,
	}
	history := &cobra.Command{
		Use:   "history <list>",
		Short: "Show the change history of a list",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.runHistory(cmd, args)
		},
	}
	history.Flags().Int("limit", 0, "only the newest N entries")
	history.Flags().StringP("output", "o", "json", "output format: json or table")
	cmd.AddCommand(accept, history)
	return cmd
}

func (c *cli) runAccept(cmd *cobra.Command, args []string) error {
	cfg, err := c.loadConfig(cmd)
	if err != nil {
		return err
	}
	return iplists.AcceptReport(cfg.IPListDir, cfg.IPSources, args[0], c.stdout)
}

func (c *cli) runHistory(cmd *cobra.Command, args []string) error {
	cfg, err := c.loadConfig(cmd)
	if err != nil {
		return err
	}
	limit, _ := cmd.Flags().GetInt("limit")
	if limit < 0 {
		return usageErrorf("--limit must not be negative")
	}
	output, _ := cmd.Flags().GetString("output")
	if output != "json" && output != "table" {
		return usageErrorf("--output %q: want json or table", output)
	}
	if _, ok := cfg.IPLists[args[0]]; !ok {
		return fmt.Errorf("%q is not a list in the config", args[0])
	}
	doc := report.NewHistory(args[0], iplists.ReadHistory(cfg.IPListDir, args[0], limit))
	if output == "table" {
		return writeHistoryTable(c.stdout, doc)
	}
	return writeJSON(c.stdout, doc)
}

func writeHistoryTable(w io.Writer, h report.History) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME\tEVENT\tPROVIDER\tBEFORE\tAFTER\tADDED\tREMOVED")
	for _, e := range h.Entries {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%d\t%d\n", e.Time, e.Event, e.Provider, e.CountBefore, e.CountAfter, e.AddedCount, e.RemovedCount)
	}
	return tw.Flush()
}
