package app

import (
	"fmt"
	"strings"
)

// migrationNote explains the change of the status JSON.
const migrationNote = "https://github.com/KazuhaHub/infra-hub/pull/2"

// Spellings of the first releases, kept as hidden aliases for one release: the private infra repository's role and
// timer call them. Each use prints a warning on stderr.
var legacyFlags = map[string]string{
	"-config":  "--config",
	"-no-refs": "--no-refs",
	"-limit":   "--limit",
}

// rewriteLegacyFlags turns the single-dash flags of the old command line into their --long form. It returns the
// new arguments, one warning per old spelling used, and whether the old `-config` spelling was among them.
func rewriteLegacyFlags(args []string) (out []string, warnings []string, legacyConfig bool) {
	isStatus := false
	for _, a := range args {
		if a == "--" {
			break
		}
		if a == "status" {
			isStatus = true
		}
	}
	out = make([]string, 0, len(args))
	warned := map[string]bool{}
	for i, a := range args {
		if a == "--" {
			out = append(out, args[i:]...)
			break
		}
		name, value, hasValue := strings.Cut(a, "=")
		if long, ok := legacyFlags[name]; ok {
			if !warned[name] {
				warned[name] = true
				msg := fmt.Sprintf("%s is deprecated and will be removed in the next release; use %s", name, long)
				if name == "-config" && isStatus {
					// Plain --config would switch status to the table and the new JSON keys: say what keeps a script working.
					msg = "-config is deprecated and will be removed in the next release. For status, use \"--config <file> -o json\" " +
						"(the JSON keys change, see the migration note: " + migrationNote + ") or \"--config <file> --format legacy\" to keep the old output"
				}
				warnings = append(warnings, msg)
			}
			if name == "-config" {
				legacyConfig = true
			}
			if hasValue {
				a = long + "=" + value
			} else {
				a = long
			}
		}
		out = append(out, a)
	}
	return out, warnings, legacyConfig
}

func deprecatedCommand(c *cli, old, replacement string) {
	fmt.Fprintf(c.stderr, "%s: warning: %s is deprecated and will be removed in the next release; use %s\n", program, old, replacement)
}
