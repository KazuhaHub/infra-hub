package app

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/KazuhaHub/infra-hub/internal/hubkey"
	"github.com/KazuhaHub/infra-hub/internal/hubtrust"
	"github.com/KazuhaHub/infra-hub/internal/jointoken"
)

func checkOutput(cmd *cobra.Command) (asJSON bool, err error) {
	output, _ := cmd.Flags().GetString("output")
	if output != "table" && output != "json" {
		return false, usageErrorf("--output %q: want table or json", output)
	}
	return output == "json", nil
}

// newKey is the hub identity key commands: one Ed25519 key shared by every hub, whose pin is what agents trust.
func (c *cli) newKey() *cobra.Command {
	k := &cobra.Command{
		Use:   "key",
		Short: "The hub identity key (generate it once, share it with every hub)",
		Long: "The hub identity key is one Ed25519 key that every hub (primary and standbys) uses. Each hub builds a self-signed\n" +
			"certificate from it at start; agents trust a hub if and only if its key matches a pin. There is no certificate to\n" +
			"renew. See docs/hub-key.md.",
		Args: usageArgs(cobra.NoArgs),
		RunE: func(*cobra.Command, []string) error {
			return usageErrorf("a key command is required: init or pin")
		},
	}
	k.AddCommand(c.newKeyInit(), c.newKeyPin())
	return k
}

func (c *cli) newKeyInit() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init --out <path>",
		Short: "Generate the hub identity key and print its pin",
		Long: "Writes a new Ed25519 key (PKCS#8 PEM, mode 0600) to <path> and prints its pin (sha256//<base64>). It refuses to\n" +
			"overwrite an existing file. The key is not encrypted: store it in SOPS at once and delete the plain file\n" +
			"(docs/hub-key.md). The pin is public.",
		Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			asJSON, err := checkOutput(cmd)
			if err != nil {
				return err
			}
			out, _ := cmd.Flags().GetString("out")
			if out == "" {
				return usageErrorf("--out is required")
			}
			key, err := hubkey.Generate()
			if err != nil {
				return fmt.Errorf("key init: %w", err)
			}
			if err := hubkey.WriteNew(out, key); err != nil {
				return fmt.Errorf("key init: %w", err)
			}
			pin, err := hubkey.Pin(key)
			if err != nil {
				return fmt.Errorf("key init: %w", err)
			}
			if asJSON {
				return writeJSON(c.stdout, struct {
					APIVersion string `json:"apiVersion"`
					Path       string `json:"path"`
					Pin        string `json:"pin"`
				}{"v1", out, pin})
			}
			fmt.Fprintln(c.stdout, pin)
			return nil
		},
	}
	cmd.Flags().String("out", "", "where to write the new key (must not exist)")
	cmd.Flags().StringP("output", "o", "table", "output format: table or json")
	return cmd
}

func (c *cli) newKeyPin() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pin --key <path>",
		Short: "Print the pin of a hub identity key",
		Long:  "Prints the pin (sha256//<base64>) of the key's public half. The pin is public; the key file is only read.",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			asJSON, err := checkOutput(cmd)
			if err != nil {
				return err
			}
			path, _ := cmd.Flags().GetString("key")
			if path == "" {
				return usageErrorf("--key is required")
			}
			pin, err := pinOfFile(path)
			if err != nil {
				return fmt.Errorf("key pin: %w", err)
			}
			if asJSON {
				return writeJSON(c.stdout, struct {
					APIVersion string `json:"apiVersion"`
					Pin        string `json:"pin"`
				}{"v1", pin})
			}
			fmt.Fprintln(c.stdout, pin)
			return nil
		},
	}
	cmd.Flags().String("key", "", "the hub identity key file")
	cmd.Flags().StringP("output", "o", "table", "output format: table or json")
	return cmd
}

func pinOfFile(path string) (string, error) {
	key, err := hubkey.Read(path)
	if err != nil {
		return "", err
	}
	return hubkey.Pin(key)
}

func (c *cli) newToken() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token (--pin <pin> | --key <path>) --hub <url> [--hub <url>...]",
		Short: "Print the one-line token for an agent install",
		Long: "Prints one line, `ih1.` plus base64url of {\"v\":1,\"pins\":[\"sha256//...\"],\"hubs\":[\"https://host:port\",...]}, to be\n" +
			"passed to the agent install: curl ... | sh -s -- <token>.\n\n" +
			"The pins come from --pin (repeatable; the public pin from the inventory, so no private key is needed) and\n" +
			"from --key (its pin is computed; the file is only read). Both may be given. The pin of --key comes first, then\n" +
			"the --pin values in the order given; a pin that is repeated is listed once. At least one pin is required. During\n" +
			"a key rotation give both the old and the new pin.\n\n" +
			"The token holds no secret: only public pins and the hubs' URLs.",
		Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			asJSON, err := checkOutput(cmd)
			if err != nil {
				return err
			}
			path, _ := cmd.Flags().GetString("key")
			given, _ := cmd.Flags().GetStringArray("pin")
			hubs, _ := cmd.Flags().GetStringArray("hub")
			if path == "" && len(given) == 0 {
				return usageErrorf("at least one --pin or a --key is required")
			}
			if len(hubs) == 0 {
				return usageErrorf("at least one --hub is required")
			}
			seen := map[string]bool{}
			for i, h := range hubs {
				h = strings.TrimSuffix(h, "/")
				if err := jointoken.ValidateHubURL(h); err != nil {
					return usageErrorf("--hub: %v", err)
				}
				if seen[h] {
					return usageErrorf("--hub: %s twice", h)
				}
				seen[h] = true
				hubs[i] = h
			}
			for _, p := range given {
				if _, err := hubtrust.ParsePin(p); err != nil {
					return usageErrorf("--pin %q: %v", p, err)
				}
			}
			var pins []string
			seen = map[string]bool{}
			add := func(p string) {
				if !seen[p] {
					seen[p] = true
					pins = append(pins, p)
				}
			}
			if path != "" {
				pin, err := pinOfFile(path)
				if err != nil {
					return fmt.Errorf("token: %w", err)
				}
				add(pin)
			}
			for _, p := range given {
				add(p)
			}
			tok, err := jointoken.Encode(pins, hubs)
			if err != nil {
				return fmt.Errorf("token: %w", err)
			}
			if asJSON {
				return writeJSON(c.stdout, struct {
					APIVersion string   `json:"apiVersion"`
					Token      string   `json:"token"`
					Pins       []string `json:"pins"`
					Hubs       []string `json:"hubs"`
				}{"v1", tok, pins, hubs})
			}
			fmt.Fprintln(c.stdout, tok)
			return nil
		},
	}
	cmd.Flags().String("key", "", "a hub identity key file (optional; only its pin is used)")
	cmd.Flags().StringArray("pin", nil, "a public pin, sha256//<base64> (repeatable)")
	cmd.Flags().StringArray("hub", nil, "a hub's URL, https://host:port (repeatable)")
	cmd.Flags().StringP("output", "o", "table", "output format: table or json")
	return cmd
}
