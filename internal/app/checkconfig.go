package app

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/KazuhaHub/infra-hub/internal/state"
)

// newCheckConfig loads the config the way serve does and reads the state file, and starts nothing. It does not
// open the hub identity key or the Cloudflare token (they may exist only inside the running service) and never
// touches the network. Used to test a new binary before switching to it.
func (c *cli) newCheckConfig() *cobra.Command {
	return &cobra.Command{
		Use:   "check-config",
		Short: "Validate the config and the existing state file, then exit",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := c.loadConfig(cmd)
			if err != nil {
				return err
			}
			if err := checkListen(cfg); err != nil {
				return err
			}
			// LoadState only reads; a missing file is an empty state.
			if _, err := state.LoadState(cfg.State); err != nil {
				return fmt.Errorf("state %s: %w", cfg.State, err)
			}
			fmt.Fprintf(c.stdout, "config ok: https %s, %d clients, %d certs, %d ip lists\n",
				cfg.HTTPS.Listen, len(cfg.Clients), len(cfg.Certs), len(cfg.IPLists))
			return nil
		},
	}
}
