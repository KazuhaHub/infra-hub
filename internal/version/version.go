// Package version holds the build identity of the programs. The release workflow sets the variables with
// -ldflags "-X github.com/KazuhaHub/infra-hub/internal/version.Version=0.2.0 ...".
package version

import "fmt"

var (
	// Version is the release number without the leading "v"; "dev" for a build that is not a release.
	Version = "dev"
	// Commit is the short commit hash the binary was built from.
	Commit = "unknown"
	// Date is the date of the commit that was built, YYYY-MM-DD, UTC.
	Date = "unknown"
)

// String is what `--version` prints: "infra-hub 0.2.0 (commit abcdef0, built 2026-11-19)".
func String(program string) string {
	return fmt.Sprintf("%s %s (commit %s, built %s)", program, Version, Commit, Date)
}
