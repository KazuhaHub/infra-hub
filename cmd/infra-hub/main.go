// Command infra-hub is the hub: it mirrors the config repository and serves the signed config bundle, certificates and
// IP lists to its agents over HTTPS. See README.md and docs/design.md.
//
//	infra-hub serve   [--config file]
//	infra-hub check-config [--config file]
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
