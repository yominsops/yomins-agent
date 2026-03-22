package upgrade

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const githubAPILatest = "https://api.github.com/repos/yominsops/yomins-agent/releases/latest"

// latestRelease queries the GitHub Releases API and returns the tag name of
// the latest final release (e.g. "v1.2.3"). Pre-release tags are returned as-is
// and will be rejected downstream by isNewer/parseVersion.
func latestRelease(ctx context.Context, currentVersion string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubAPILatest, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "yomins-agent/"+currentVersion)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("github api request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github api returned %s", resp.Status)
	}

	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if rel.TagName == "" {
		return "", fmt.Errorf("github api returned empty tag_name")
	}
	return rel.TagName, nil
}
