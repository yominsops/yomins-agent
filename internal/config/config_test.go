package config_test

import (
	"os"
	"testing"
	"time"

	"github.com/yominsops/yomins-agent/internal/config"
)

// loadWithArgs is a helper that temporarily replaces os.Args and calls Load().
func loadWithArgs(args []string) (*config.Config, error) {
	old := os.Args
	defer func() { os.Args = old }()
	os.Args = append([]string{"yomins-agent"}, args...)
	return config.Load()
}

func TestLoad_Defaults(t *testing.T) {
	clearEnv(t)
	cfg, err := loadWithArgs([]string{"--server=http://example.com", "--token=tok"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Interval != 60*time.Second {
		t.Errorf("Interval = %v, want 60s", cfg.Interval)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want info", cfg.LogLevel)
	}
	if cfg.StateDir != "/var/lib/yomins-agent" {
		t.Errorf("StateDir = %q, want /var/lib/yomins-agent", cfg.StateDir)
	}
}

func TestLoad_CLIFlagsPrecedence(t *testing.T) {
	clearEnv(t)
	t.Setenv("YOMINS_SERVER", "http://from-env.com")
	t.Setenv("YOMINS_TOKEN", "env-token")

	cfg, err := loadWithArgs([]string{"--server=http://from-flag.com", "--token=flag-token"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server != "http://from-flag.com" {
		t.Errorf("Server = %q, want flag value", cfg.Server)
	}
	if cfg.Token != "flag-token" {
		t.Errorf("Token = %q, want flag value", cfg.Token)
	}
}

func TestLoad_EnvVarFallback(t *testing.T) {
	clearEnv(t)
	t.Setenv("YOMINS_SERVER", "http://env-server.com")
	t.Setenv("YOMINS_TOKEN", "env-tok")
	t.Setenv("YOMINS_INTERVAL", "30s")
	t.Setenv("YOMINS_LOG_LEVEL", "debug")

	cfg, err := loadWithArgs([]string{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server != "http://env-server.com" {
		t.Errorf("Server = %q, want env value", cfg.Server)
	}
	if cfg.Token != "env-tok" {
		t.Errorf("Token = %q, want env value", cfg.Token)
	}
	if cfg.Interval != 30*time.Second {
		t.Errorf("Interval = %v, want 30s", cfg.Interval)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want debug", cfg.LogLevel)
	}
}

func TestLoad_DisableFlags(t *testing.T) {
	clearEnv(t)
	t.Setenv("YOMINS_DISABLE_FILESYSTEMS", "true")
	t.Setenv("YOMINS_DISABLE_NETWORK", "1")

	cfg, err := loadWithArgs([]string{"--server=s", "--token=t"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.DisableFilesystems {
		t.Error("DisableFilesystems should be true from env")
	}
	if !cfg.DisableNetwork {
		t.Error("DisableNetwork should be true from env")
	}
}

func TestValidate_MissingServer(t *testing.T) {
	cfg := &config.Config{Token: "tok", Interval: 60 * time.Second}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for missing server")
	}
}

func TestValidate_MissingToken(t *testing.T) {
	cfg := &config.Config{Server: "http://x.com", Interval: 60 * time.Second}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for missing token")
	}
}

func TestValidate_InvalidInterval(t *testing.T) {
	cfg := &config.Config{Server: "http://x.com", Token: "tok", Interval: 0}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for zero interval")
	}
}

func TestValidate_Valid(t *testing.T) {
	cfg := &config.Config{Server: "http://x.com", Token: "tok", Interval: 60 * time.Second}
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoad_ExcludeFiltersFlags(t *testing.T) {
	clearEnv(t)
	cfg, err := loadWithArgs([]string{
		"--server=http://x.com", "--token=t",
		"--exclude-mountpoints=/proc,/sys, /dev/shm ",
		"--exclude-interfaces=docker0, virbr0",
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	wantMP := []string{"/proc", "/sys", "/dev/shm"}
	if len(cfg.ExcludeMountpoints) != len(wantMP) {
		t.Fatalf("ExcludeMountpoints = %v, want %v", cfg.ExcludeMountpoints, wantMP)
	}
	for i, v := range wantMP {
		if cfg.ExcludeMountpoints[i] != v {
			t.Errorf("ExcludeMountpoints[%d] = %q, want %q", i, cfg.ExcludeMountpoints[i], v)
		}
	}
	wantIF := []string{"docker0", "virbr0"}
	if len(cfg.ExcludeInterfaces) != len(wantIF) {
		t.Fatalf("ExcludeInterfaces = %v, want %v", cfg.ExcludeInterfaces, wantIF)
	}
	for i, v := range wantIF {
		if cfg.ExcludeInterfaces[i] != v {
			t.Errorf("ExcludeInterfaces[%d] = %q, want %q", i, cfg.ExcludeInterfaces[i], v)
		}
	}
}

func TestLoad_ExcludeFiltersEnv(t *testing.T) {
	clearEnv(t)
	t.Setenv("YOMINS_EXCLUDE_MOUNTPOINTS", "/proc,/sys")
	t.Setenv("YOMINS_EXCLUDE_INTERFACES", "docker0")

	cfg, err := loadWithArgs([]string{"--server=http://x.com", "--token=t"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.ExcludeMountpoints) != 2 {
		t.Errorf("ExcludeMountpoints = %v, want 2 entries", cfg.ExcludeMountpoints)
	}
	if len(cfg.ExcludeInterfaces) != 1 || cfg.ExcludeInterfaces[0] != "docker0" {
		t.Errorf("ExcludeInterfaces = %v, want [docker0]", cfg.ExcludeInterfaces)
	}
}

func TestLoad_ExcludeFiltersEmpty(t *testing.T) {
	clearEnv(t)
	cfg, err := loadWithArgs([]string{"--server=http://x.com", "--token=t"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ExcludeMountpoints != nil {
		t.Errorf("ExcludeMountpoints = %v, want nil", cfg.ExcludeMountpoints)
	}
	if cfg.ExcludeInterfaces != nil {
		t.Errorf("ExcludeInterfaces = %v, want nil", cfg.ExcludeInterfaces)
	}
}

// clearEnv removes all YOMINS_* environment variables so tests start clean.
func clearEnv(t *testing.T) {
	t.Helper()
	vars := []string{
		"YOMINS_SERVER", "YOMINS_TOKEN", "YOMINS_INTERVAL", "YOMINS_LOG_LEVEL",
		"YOMINS_HOSTNAME_OVERRIDE", "YOMINS_DISABLE_FILESYSTEMS",
		"YOMINS_DISABLE_NETWORK", "YOMINS_STATE_DIR",
		"YOMINS_EXCLUDE_MOUNTPOINTS", "YOMINS_EXCLUDE_INTERFACES",
	}
	for _, v := range vars {
		t.Setenv(v, "") // t.Setenv restores original value on cleanup
		os.Unsetenv(v)
	}
}
