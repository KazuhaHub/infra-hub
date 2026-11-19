package app

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/KazuhaHub/infra-hub/internal/atomicfile"
	"github.com/KazuhaHub/infra-hub/internal/config"
	"github.com/KazuhaHub/infra-hub/internal/httpsapi"
	"github.com/KazuhaHub/infra-hub/internal/hubca"
)

// newCA is the hub CA tooling. It is for the owner's workstation: a server never needs the CA key.
func (c *cli) newCA() *cobra.Command {
	ca := &cobra.Command{
		Use:   "ca",
		Short: "Hub CA tooling (run on a workstation, never on a server)",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(*cobra.Command, []string) error {
			return usageErrorf("a ca command is required: init, sign or pin")
		},
	}
	ca.AddCommand(c.newCAInit(), c.newCASign(), c.newCAPin())
	return ca
}

func (c *cli) newCAInit() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init --out <dir>",
		Short: "Create a CA key and a self-signed CA certificate (20 years) and print the CA pin",
		Long: "Creates ca.key (ECDSA P-256, mode 0600, not encrypted: encrypt it at once, see docs/ca.md) and ca.crt in <dir>.\n" +
			"Prints the CA public-key pin in curl's --pinnedpubkey form. With --permit-ip / --permit-dns the CA can only ever\n" +
			"certify those names (a critical name constraint).",
		Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, _ := cmd.Flags().GetString("out")
			if out == "" {
				return usageErrorf("--out is required")
			}
			var cons hubca.Constraints
			ips, _ := cmd.Flags().GetStringArray("permit-ip")
			for _, s := range ips {
				p, err := hubca.ParsePrefix(s)
				if err != nil {
					return usageErrorf("--permit-ip: %v", err)
				}
				cons.IPs = append(cons.IPs, p)
			}
			cons.Names, _ = cmd.Flags().GetStringArray("permit-dns")
			pin, err := hubca.Init(out, c.now(), cons)
			if err != nil {
				return fmt.Errorf("ca init: %w", err)
			}
			fmt.Fprintln(c.stdout, pin)
			return nil
		},
	}
	cmd.Flags().String("out", "", "directory for ca.key and ca.crt")
	cmd.Flags().StringArray("permit-ip", nil, "only certify IP addresses inside this CIDR range (repeatable)")
	cmd.Flags().StringArray("permit-dns", nil, "only certify this DNS domain and its sub-domains (repeatable)")
	return cmd
}

func (c *cli) newCASign() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign --ca-key K --ca-cert C --csr hub.csr --out hub.crt [--days 825]",
		Short: "Sign a hub's certificate request",
		Long:  "The names are taken from the request; only IP and DNS names are accepted. Prints the certificate's serial and expiry.",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			f := cmd.Flags()
			keyPath, _ := f.GetString("ca-key")
			certPath, _ := f.GetString("ca-cert")
			csrPath, _ := f.GetString("csr")
			out, _ := f.GetString("out")
			days, _ := f.GetInt("days")
			if keyPath == "" || certPath == "" || csrPath == "" || out == "" {
				return usageErrorf("--ca-key, --ca-cert, --csr and --out are required")
			}
			key, err := hubca.ReadPrivateKey(keyPath)
			if err != nil {
				return fmt.Errorf("ca sign: %w", err)
			}
			caCert, err := hubca.ReadCertificate(certPath)
			if err != nil {
				return fmt.Errorf("ca sign: %s: %w", certPath, err)
			}
			csr, err := os.ReadFile(csrPath)
			if err != nil {
				return fmt.Errorf("ca sign: %w", err)
			}
			pemOut, cert, err := hubca.Sign(hubca.SignOptions{CAKey: key, CACert: caCert, CSRPEM: csr, Days: days, Now: c.now()})
			if err != nil {
				return fmt.Errorf("ca sign: %w", err)
			}
			if err := atomicfile.Write(out, pemOut, 0o644); err != nil {
				return fmt.Errorf("ca sign: %w", err)
			}
			fmt.Fprintf(c.stdout, "signed %s\nserial:    %s\nnot after: %s\nhub pin:   %s\n", out, cert.SerialNumber.Text(16), cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"), hubca.Pin(cert))
			return nil
		},
	}
	cmd.Flags().String("ca-key", "", "the CA private key (decrypted, on the workstation)")
	cmd.Flags().String("ca-cert", "", "the CA certificate")
	cmd.Flags().String("csr", "", "the hub's certificate request")
	cmd.Flags().String("out", "", "where to write the signed certificate")
	cmd.Flags().Int("days", hubca.DefaultDays, "validity in days (at most 825)")
	return cmd
}

func (c *cli) newCAPin() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pin --cert C",
		Short: "Print the public-key pin of a certificate (curl --pinnedpubkey form)",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, _ := cmd.Flags().GetString("cert")
			if path == "" {
				return usageErrorf("--cert is required")
			}
			cert, err := hubca.ReadCertificate(path)
			if err != nil {
				return fmt.Errorf("ca pin: %s: %w", path, err)
			}
			fmt.Fprintln(c.stdout, hubca.Pin(cert))
			return nil
		},
	}
	cmd.Flags().String("cert", "", "certificate file (PEM)")
	return cmd
}

// newHTTPS is the hub's HTTPS identity commands.
func (c *cli) newHTTPS() *cobra.Command {
	h := &cobra.Command{
		Use:   "https",
		Short: "The hub's HTTPS identity",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(*cobra.Command, []string) error {
			return usageErrorf("an https command is required: csr")
		},
	}
	h.AddCommand(&cobra.Command{
		Use:   "csr",
		Short: "Print the hub's certificate request (creates the hub's TLS key on first use)",
		Long: "Prints the PEM certificate request for httpsAddresses. Run it as the user that runs the hub, so that the key is\n" +
			"owned by that user. Sign the request with `infra-hub ca sign` on the owner's workstation.",
		Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := c.loadConfig(cmd)
			if err != nil {
				return err
			}
			if len(cfg.HTTPSAddresses) == 0 {
				return fmt.Errorf("https csr: httpsAddresses is empty in the config")
			}
			csr, err := httpsIdentity(cfg).EnsureCSR()
			if err != nil {
				return fmt.Errorf("https csr: %w", err)
			}
			_, err = c.stdout.Write(csr)
			return err
		},
	})
	return h
}

// httpsIdentity places the hub's key and request in the state directory (next to the state file).
func httpsIdentity(cfg config.Config) httpsapi.Identity {
	dir := filepath.Dir(cfg.State)
	return httpsapi.Identity{KeyPath: filepath.Join(dir, "hub-https.key"), CSRPath: filepath.Join(dir, "hub.csr"),
		CertPath: cfg.HTTPS.Cert, CAPath: cfg.HTTPS.CACert, Addresses: cfg.HTTPSAddresses}
}
