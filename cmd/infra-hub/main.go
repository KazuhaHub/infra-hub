// Command infra-hub is the hub: a read-only git mirror of the config repository served over SSH to the hosts that
// are listed in its config, plus certificates and IP lists. See README.md and docs/design.md.
//
//	infra-hub serve   [--config file]
//	infra-hub status  [--config file] [-o json]
//	infra-hub iplist accept  <provider>
//	infra-hub iplist history <list> [--limit N]
//	infra-hub version
package main

import (
	"os"

	"github.com/KazuhaHub/infra-hub/internal/app"
)

func main() { os.Exit(app.Main(os.Args[1:], os.Stdout, os.Stderr)) }
