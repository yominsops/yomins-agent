package upgrade

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const githubDownloadBase = "https://github.com/yominsops/yomins-agent/releases/download"

// platformAsset returns the release asset name for the current platform,
// e.g. "yomins-agent-linux-amd64".
func platformAsset() (string, error) {
	if runtime.GOOS != "linux" {
		return "", fmt.Errorf("unsupported OS %q: auto-upgrade only supported on linux", runtime.GOOS)
	}
	switch runtime.GOARCH {
	case "amd64", "arm64":
		return "yomins-agent-linux-" + runtime.GOARCH, nil
	default:
		return "", fmt.Errorf("unsupported architecture %q", runtime.GOARCH)
	}
}

// stageUpgrade downloads the release binary for the given tag, verifies its
// SHA256 checksum, and writes it to <stateDir>/upgrade/new (mode 0600).
// The pending marker is NOT written here; the caller does that.
func stageUpgrade(ctx context.Context, stateDir, tag string) error {
	asset, err := platformAsset()
	if err != nil {
		return err
	}

	upgradeDir := filepath.Join(stateDir, "upgrade")
	if err := os.MkdirAll(upgradeDir, 0700); err != nil {
		return fmt.Errorf("create upgrade dir: %w", err)
	}

	binaryURL := githubDownloadBase + "/" + tag + "/" + asset
	checksumURL := binaryURL + ".sha256"

	// Download binary to a temp file first.
	tmpPath := filepath.Join(upgradeDir, "new.tmp")
	if err := downloadFile(ctx, binaryURL, tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("download binary: %w", err)
	}

	// Download the per-file .sha256 sidecar.
	checksumPath := filepath.Join(upgradeDir, "new.sha256")
	if err := downloadFile(ctx, checksumURL, checksumPath); err != nil {
		_ = os.Remove(tmpPath)
		_ = os.Remove(checksumPath)
		return fmt.Errorf("download checksum: %w", err)
	}

	// Verify checksum before accepting the binary.
	if err := verifyChecksum(tmpPath, checksumPath); err != nil {
		_ = os.Remove(tmpPath)
		_ = os.Remove(checksumPath)
		return fmt.Errorf("checksum verification failed: %w", err)
	}
	_ = os.Remove(checksumPath)

	// Rename temp to final staged path.
	newPath := filepath.Join(upgradeDir, "new")
	if err := os.Rename(tmpPath, newPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("stage binary: %w", err)
	}

	return nil
}

// downloadFile fetches url and writes the response body to dest (mode 0600).
func downloadFile(ctx context.Context, url, dest string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %s", resp.Status)
	}

	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	return f.Close()
}

// verifyChecksum reads the SHA256 hex digest from checksumFile (first word on
// the first line, matching the format produced by sha256sum) and compares it
// against the actual digest of binaryFile.
func verifyChecksum(binaryFile, checksumFile string) error {
	raw, err := os.ReadFile(checksumFile)
	if err != nil {
		return fmt.Errorf("read checksum file: %w", err)
	}
	// "sha256sum" output: "<hex>  <filename>\n"
	expected := strings.TrimSpace(strings.Fields(string(raw))[0])
	if len(expected) != 64 {
		return fmt.Errorf("unexpected checksum format: %q", string(raw))
	}

	f, err := os.Open(binaryFile)
	if err != nil {
		return fmt.Errorf("open binary: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("hash binary: %w", err)
	}
	actual := hex.EncodeToString(h.Sum(nil))

	if actual != expected {
		return fmt.Errorf("checksum mismatch: got %s, want %s", actual, expected)
	}
	return nil
}
