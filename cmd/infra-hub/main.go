// Command infra-hub is the hub: a read-only git mirror of the config repository served over SSH to the hosts that
// are listed in its config, plus certificates and IP lists. See README.md and docs/design.md.
//
//	infra-hub serve  -config /etc/infra-hub/config.json
//	infra-hub status -config /etc/infra-hub/config.json
//	infra-hub iplist-accept [-config file] <provider>   apply a held IP list update
//	infra-hub iplist-history [-config file] <list> [--limit N]   JSON change history of a list
package main

import "github.com/KazuhaHub/infra-hub/internal/app"

func main() { app.Main() }
