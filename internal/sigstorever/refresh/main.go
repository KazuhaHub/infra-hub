// Command refresh downloads the public-good Sigstore trusted root through TUF (starting from the root.json that
// sigstore-go embeds, so every file is checked against the Sigstore root of trust) and writes it where the agent
// embeds it. It is run by hand when a release refreshes the root:
//
//	go run ./internal/sigstorever/refresh internal/sigstorever/trusted_root.json
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: refresh <output file>")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "refresh:", err)
		os.Exit(1)
	}
}

func run(out string) error {
	cache, err := os.MkdirTemp("", "sigstore-tuf-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(cache)
	opts := tuf.DefaultOptions()
	opts.CachePath = filepath.Join(cache, "tuf")
	client, err := tuf.New(opts)
	if err != nil {
		return err
	}
	data, err := client.GetTarget("trusted_root.json")
	if err != nil {
		return err
	}
	if _, err := root.NewTrustedRootFromJSON(data); err != nil {
		return fmt.Errorf("the downloaded trusted root does not parse: %w", err)
	}
	return os.WriteFile(out, data, 0o644)
}
