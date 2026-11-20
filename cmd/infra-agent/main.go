// Command infra-agent is the per-machine agent: it fetches this host's config bundle from the hubs over HTTPS,
// verifies it, applies it with ansible and reports the result. See docs/agent.md.
//
//	infra-agent run [--once] [--env-file file]
//	infra-agent status [-o json]
//	infra-agent check-config
//	infra-agent version
package main

import (
	"os"

	"github.com/KazuhaHub/infra-hub/internal/agentapp"
)

func main() { os.Exit(agentapp.Main(os.Args[1:], os.Stdout, os.Stderr)) }
