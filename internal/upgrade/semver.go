package upgrade

import (
	"fmt"
	"strconv"
	"strings"
)

// parseVersion converts "v1.2.3" or "1.2.3" into [3]int{1, 2, 3}.
// Pre-release suffixes (e.g. "v1.2.3-rc1") are rejected so that the agent
// never auto-upgrades to a non-final release.
func parseVersion(v string) ([3]int, error) {
	v = strings.TrimPrefix(v, "v")
	if strings.ContainsAny(v, "-+") {
		return [3]int{}, fmt.Errorf("pre-release version not supported: %q", v)
	}
	parts := strings.SplitN(v, ".", 3)
	if len(parts) != 3 {
		return [3]int{}, fmt.Errorf("invalid version %q: expected major.minor.patch", v)
	}
	var out [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return [3]int{}, fmt.Errorf("invalid version component %q in %q", p, v)
		}
		out[i] = n
	}
	return out, nil
}

// isNewer returns true if candidate is strictly greater than current.
func isNewer(current, candidate string) (bool, error) {
	c, err := parseVersion(current)
	if err != nil {
		return false, fmt.Errorf("parse current version: %w", err)
	}
	n, err := parseVersion(candidate)
	if err != nil {
		return false, fmt.Errorf("parse candidate version: %w", err)
	}
	for i := range c {
		if n[i] > c[i] {
			return true, nil
		}
		if n[i] < c[i] {
			return false, nil
		}
	}
	return false, nil // equal
}
