package version

import "fmt"

// These variables are injected at build time via -ldflags.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// Info returns a human-readable version string.
func Info() string {
	return fmt.Sprintf("%s (commit=%s, built=%s)", Version, Commit, BuildDate)
}
