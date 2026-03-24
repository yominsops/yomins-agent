package collector_test

import (
	"context"
	"errors"
	"testing"

	"github.com/yominsops/yomins-agent/internal/collector"
)

type mockInfoReader struct {
	sysInfo  *collector.SystemInfoStat
	sysErr   error
	cpuInfo  *collector.CPUInfoStat
	cpuErr   error
	pkgTimes *collector.PackageUpdateTimes
	pkgErr   error
	kcInfo   *collector.KernelCareInfoStat
	kcErr    error
}

func (m *mockInfoReader) SystemInfoWithContext(_ context.Context) (*collector.SystemInfoStat, error) {
	return m.sysInfo, m.sysErr
}
func (m *mockInfoReader) CPUInfoWithContext(_ context.Context) (*collector.CPUInfoStat, error) {
	return m.cpuInfo, m.cpuErr
}
func (m *mockInfoReader) PackageUpdateTimesWithContext(_ context.Context) (*collector.PackageUpdateTimes, error) {
	return m.pkgTimes, m.pkgErr
}
func (m *mockInfoReader) KernelCareInfoWithContext(_ context.Context) (*collector.KernelCareInfoStat, error) {
	return m.kcInfo, m.kcErr
}

func newFullMock() *mockInfoReader {
	return &mockInfoReader{
		sysInfo: &collector.SystemInfoStat{
			Distribution:        "ubuntu",
			DistributionVersion: "22.04",
			KernelVersion:       "5.15.0-107-generic",
			Virtualization:      "kvm",
		},
		cpuInfo: &collector.CPUInfoStat{
			Model:   "Intel(R) Xeon(R) Silver 4110 CPU @ 2.10GHz",
			Cores:   8,
			Threads: 16,
		},
		pkgTimes: &collector.PackageUpdateTimes{
			LastKernelUpdate:   1710000000,
			LastSoftwareUpdate: 1710100000,
		},
		kcInfo: &collector.KernelCareInfoStat{
			Installed: true,
			Version:   "2.56.1",
		},
	}
}

func findPoint(pts []interface{ GetName() string }, name string) bool {
	for _, p := range pts {
		if p.GetName() == name {
			return true
		}
	}
	return false
}

func countByName(pts []struct{ Name string }, name string) int {
	n := 0
	for _, p := range pts {
		if p.Name == name {
			n++
		}
	}
	return n
}

func TestInfoCollector_Name(t *testing.T) {
	c := collector.NewInfoCollectorWithReader(&mockInfoReader{}, collector.InfoConfig{})
	if c.Name() != "info" {
		t.Errorf("Name() = %q, want %q", c.Name(), "info")
	}
}

func TestInfoCollector_AllDataPresent(t *testing.T) {
	c := collector.NewInfoCollectorWithReader(newFullMock(), collector.InfoConfig{})
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pts) != 5 {
		t.Fatalf("expected 5 points, got %d: %v", len(pts), pts)
	}

	names := make(map[string]bool, len(pts))
	for _, p := range pts {
		names[p.Name] = true
	}
	for _, want := range []string{
		"system_info",
		"cpu_info",
		"system_last_kernel_update_timestamp",
		"system_last_software_update_timestamp",
		"kernelcare_info",
	} {
		if !names[want] {
			t.Errorf("missing metric %q", want)
		}
	}
}

func TestInfoCollector_SystemInfoLabels(t *testing.T) {
	c := collector.NewInfoCollectorWithReader(newFullMock(), collector.InfoConfig{})
	pts, _ := c.Collect(context.Background())
	for _, p := range pts {
		if p.Name != "system_info" {
			continue
		}
		if p.Labels["distribution"] != "ubuntu" {
			t.Errorf("distribution = %q", p.Labels["distribution"])
		}
		if p.Labels["distribution_version"] != "22.04" {
			t.Errorf("distribution_version = %q", p.Labels["distribution_version"])
		}
		if p.Labels["kernel_version"] != "5.15.0-107-generic" {
			t.Errorf("kernel_version = %q", p.Labels["kernel_version"])
		}
		if p.Labels["virtualization"] != "kvm" {
			t.Errorf("virtualization = %q", p.Labels["virtualization"])
		}
		return
	}
	t.Error("system_info metric not found")
}

func TestInfoCollector_KernelCareDisabled(t *testing.T) {
	c := collector.NewInfoCollectorWithReader(newFullMock(), collector.InfoConfig{
		DisableKernelCareInfo: true,
	})
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, p := range pts {
		if p.Name == "kernelcare_info" {
			t.Error("kernelcare_info should not be emitted when DisableKernelCareInfo=true")
		}
	}
}

func TestInfoCollector_KernelCareNotInstalled(t *testing.T) {
	m := newFullMock()
	m.kcInfo = &collector.KernelCareInfoStat{Installed: false}
	c := collector.NewInfoCollectorWithReader(m, collector.InfoConfig{})
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, p := range pts {
		if p.Name == "kernelcare_info" {
			t.Error("kernelcare_info should not be emitted when not installed")
		}
	}
}

func TestInfoCollector_TimestampsAbsent(t *testing.T) {
	m := newFullMock()
	m.pkgTimes = &collector.PackageUpdateTimes{LastKernelUpdate: 0, LastSoftwareUpdate: 0}
	c := collector.NewInfoCollectorWithReader(m, collector.InfoConfig{})
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, p := range pts {
		if p.Name == "system_last_kernel_update_timestamp" || p.Name == "system_last_software_update_timestamp" {
			t.Errorf("timestamp metric %q should not be emitted when value is 0", p.Name)
		}
	}
}

func TestInfoCollector_PartialTimestamps(t *testing.T) {
	m := newFullMock()
	m.pkgTimes = &collector.PackageUpdateTimes{LastKernelUpdate: 1710000000, LastSoftwareUpdate: 0}
	c := collector.NewInfoCollectorWithReader(m, collector.InfoConfig{})
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	kernelCount := 0
	softwareCount := 0
	for _, p := range pts {
		if p.Name == "system_last_kernel_update_timestamp" {
			kernelCount++
		}
		if p.Name == "system_last_software_update_timestamp" {
			softwareCount++
		}
	}
	if kernelCount != 1 {
		t.Errorf("expected 1 kernel timestamp point, got %d", kernelCount)
	}
	if softwareCount != 0 {
		t.Errorf("expected 0 software timestamp points, got %d", softwareCount)
	}
}

func TestInfoCollector_SystemInfoError(t *testing.T) {
	m := newFullMock()
	m.sysInfo = nil
	m.sysErr = errors.New("permission denied")
	c := collector.NewInfoCollectorWithReader(m, collector.InfoConfig{})
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, p := range pts {
		if p.Name == "system_info" {
			t.Error("system_info should not be emitted when reader returns error")
		}
	}
}

func TestInfoCollector_CPUInfoError(t *testing.T) {
	m := newFullMock()
	m.cpuInfo = nil
	m.cpuErr = errors.New("cpu info unavailable")
	c := collector.NewInfoCollectorWithReader(m, collector.InfoConfig{})
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, p := range pts {
		if p.Name == "cpu_info" {
			t.Error("cpu_info should not be emitted when reader returns error")
		}
	}
}

func TestInfoCollector_AllReadersFail(t *testing.T) {
	m := &mockInfoReader{
		sysErr: errors.New("fail"),
		cpuErr: errors.New("fail"),
		pkgErr: errors.New("fail"),
		kcErr:  errors.New("fail"),
	}
	c := collector.NewInfoCollectorWithReader(m, collector.InfoConfig{})
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect must not return error on graceful degradation, got: %v", err)
	}
	if len(pts) != 0 {
		t.Errorf("expected 0 points when all readers fail, got %d", len(pts))
	}
}

func TestInfoCollector_CPULabelsAreStrings(t *testing.T) {
	m := newFullMock()
	m.cpuInfo = &collector.CPUInfoStat{Model: "Test CPU", Cores: 4, Threads: 8}
	c := collector.NewInfoCollectorWithReader(m, collector.InfoConfig{})
	pts, _ := c.Collect(context.Background())
	for _, p := range pts {
		if p.Name != "cpu_info" {
			continue
		}
		if p.Labels["cores"] != "4" {
			t.Errorf("cores label = %q, want %q", p.Labels["cores"], "4")
		}
		if p.Labels["threads"] != "8" {
			t.Errorf("threads label = %q, want %q", p.Labels["threads"], "8")
		}
		return
	}
	t.Error("cpu_info metric not found")
}
