package collector_test

import (
	"context"
	"errors"
	"testing"

	"github.com/yominsops/yomins-agent/internal/collector"
)

type mockInfoReader struct {
	sysInfo    *collector.SystemInfoStat
	sysErr     error
	cpuInfo    *collector.CPUInfoStat
	cpuErr     error
	pkgTimes   *collector.PackageUpdateTimes
	pkgErr     error
	kcInfo     *collector.KernelCareInfoStat
	kcErr      error
	memInfo *collector.MemoryInfo
	memErr  error
	disks      []collector.DiskHardwareStat
	diskErr    error
	nics       []collector.NetworkHardwareStat
	nicErr     error
	hwInfo     *collector.SystemHardwareStat
	hwErr      error
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
func (m *mockInfoReader) MemoryInfoWithContext(_ context.Context) (*collector.MemoryInfo, error) {
	return m.memInfo, m.memErr
}
func (m *mockInfoReader) DiskHardwareWithContext(_ context.Context) ([]collector.DiskHardwareStat, error) {
	return m.disks, m.diskErr
}
func (m *mockInfoReader) NetworkHardwareWithContext(_ context.Context) ([]collector.NetworkHardwareStat, error) {
	return m.nics, m.nicErr
}
func (m *mockInfoReader) SystemHardwareWithContext(_ context.Context) (*collector.SystemHardwareStat, error) {
	return m.hwInfo, m.hwErr
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
		memInfo: &collector.MemoryInfo{
			TotalMB: 32768,
			Modules: []collector.MemoryModuleStat{
				{SizeMB: 8192, Type: "DDR4", SpeedMhz: 2666, Manufacturer: "Samsung", Locator: "DIMM_A1"},
				{SizeMB: 8192, Type: "DDR4", SpeedMhz: 2666, Manufacturer: "Samsung", Locator: "DIMM_A2"},
				{SizeMB: 8192, Type: "DDR4", SpeedMhz: 2666, Manufacturer: "Micron", Locator: "DIMM_B1"},
				{SizeMB: 8192, Type: "DDR4", SpeedMhz: 2666, Manufacturer: "Micron", Locator: "DIMM_B2"},
			},
		},
		disks: []collector.DiskHardwareStat{
			{Device: "sda", Model: "Samsung SSD 870 EVO 1TB", SizeGB: 1000, Type: "ssd", Transport: "sata"},
			{Device: "sdb", Model: "WDC WD10EZEX", SizeGB: 1000, Type: "hdd", Transport: "sata"},
			{Device: "nvme0n1", Model: "Samsung PM9A1", SizeGB: 512, Type: "nvme", Transport: "nvme"},
		},
		nics: []collector.NetworkHardwareStat{
			{Interface: "eth0", SpeedMbps: 10000, State: "up", Duplex: "full"},
			{Interface: "eth1", SpeedMbps: 1000, State: "down", Duplex: "full"},
		},
		hwInfo: &collector.SystemHardwareStat{
			Vendor:  "Dell Inc.",
			Product: "PowerEdge R740",
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
	// 5 original + 1 memory_hardware_info + 4 memory modules + 3 disks + 2 NICs + 1 hardware_info = 16
	if len(pts) != 16 {
		t.Fatalf("expected 16 points, got %d", len(pts))
	}

	names := make(map[string]int, len(pts))
	for _, p := range pts {
		names[p.Name]++
	}
	for want, wantCount := range map[string]int{
		"system_info":                           1,
		"cpu_info":                              1,
		"system_last_kernel_update_timestamp":   1,
		"system_last_software_update_timestamp": 1,
		"kernelcare_info":                       1,
		"memory_hardware_info":                  1,
		"memory_module_info":                    4,
		"disk_hardware_info":                    3,
		"network_hardware_info":                 2,
		"hardware_info":                         1,
	} {
		if names[want] != wantCount {
			t.Errorf("metric %q: got %d points, want %d", want, names[want], wantCount)
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

func TestInfoCollector_MemoryModules(t *testing.T) {
	m := newFullMock()
	c := collector.NewInfoCollectorWithReader(m, collector.InfoConfig{})
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Assert summary metric.
	foundSummary := false
	moduleCount := 0
	for _, p := range pts {
		switch p.Name {
		case "memory_hardware_info":
			foundSummary = true
			if p.Labels["total_mb"] != "32768" {
				t.Errorf("total_mb = %q, want %q", p.Labels["total_mb"], "32768")
			}
		case "memory_module_info":
			moduleCount++
			if p.Labels["size_mb"] != "8192" {
				t.Errorf("module %s: size_mb = %q, want %q", p.Labels["index"], p.Labels["size_mb"], "8192")
			}
			if p.Labels["type"] != "DDR4" {
				t.Errorf("module %s: type = %q, want %q", p.Labels["index"], p.Labels["type"], "DDR4")
			}
		}
	}
	if !foundSummary {
		t.Error("memory_hardware_info metric not found")
	}
	if moduleCount != 4 {
		t.Errorf("expected 4 memory_module_info points, got %d", moduleCount)
	}
}

func TestInfoCollector_MemoryModulesEmpty(t *testing.T) {
	m := newFullMock()
	m.memInfo = &collector.MemoryInfo{TotalMB: 16384} // total only, no modules
	c := collector.NewInfoCollectorWithReader(m, collector.InfoConfig{})
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	foundSummary := false
	for _, p := range pts {
		switch p.Name {
		case "memory_hardware_info":
			foundSummary = true
			if p.Labels["total_mb"] != "16384" {
				t.Errorf("total_mb = %q, want %q", p.Labels["total_mb"], "16384")
			}
		case "memory_module_info":
			t.Error("memory_module_info should not be emitted when Modules is nil")
		}
	}
	if !foundSummary {
		t.Error("memory_hardware_info should still be emitted when modules are unavailable")
	}
}

func TestInfoCollector_DiskHardware(t *testing.T) {
	m := newFullMock()
	c := collector.NewInfoCollectorWithReader(m, collector.InfoConfig{})
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	typesByDevice := make(map[string]string)
	for _, p := range pts {
		if p.Name == "disk_hardware_info" {
			typesByDevice[p.Labels["device"]] = p.Labels["type"]
		}
	}
	if typesByDevice["sda"] != "ssd" {
		t.Errorf("sda type = %q, want ssd", typesByDevice["sda"])
	}
	if typesByDevice["sdb"] != "hdd" {
		t.Errorf("sdb type = %q, want hdd", typesByDevice["sdb"])
	}
	if typesByDevice["nvme0n1"] != "nvme" {
		t.Errorf("nvme0n1 type = %q, want nvme", typesByDevice["nvme0n1"])
	}
}

func TestInfoCollector_NetworkHardware(t *testing.T) {
	m := newFullMock()
	c := collector.NewInfoCollectorWithReader(m, collector.InfoConfig{})
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	nicsByIface := make(map[string]map[string]string)
	for _, p := range pts {
		if p.Name == "network_hardware_info" {
			nicsByIface[p.Labels["interface"]] = p.Labels
		}
	}
	if nicsByIface["eth0"]["speed_mbps"] != "10000" {
		t.Errorf("eth0 speed_mbps = %q, want 10000", nicsByIface["eth0"]["speed_mbps"])
	}
	if nicsByIface["eth0"]["state"] != "up" {
		t.Errorf("eth0 state = %q, want up", nicsByIface["eth0"]["state"])
	}
	if nicsByIface["eth1"]["state"] != "down" {
		t.Errorf("eth1 state = %q, want down", nicsByIface["eth1"]["state"])
	}
}

func TestInfoCollector_HardwareInfo(t *testing.T) {
	m := newFullMock()
	c := collector.NewInfoCollectorWithReader(m, collector.InfoConfig{})
	pts, _ := c.Collect(context.Background())
	for _, p := range pts {
		if p.Name != "hardware_info" {
			continue
		}
		if p.Labels["vendor"] != "Dell Inc." {
			t.Errorf("vendor = %q, want %q", p.Labels["vendor"], "Dell Inc.")
		}
		if p.Labels["product"] != "PowerEdge R740" {
			t.Errorf("product = %q, want %q", p.Labels["product"], "PowerEdge R740")
		}
		return
	}
	t.Error("hardware_info metric not found")
}

func TestInfoCollector_NewMethodsGracefulDegradation(t *testing.T) {
	m := newFullMock()
	m.memErr = errors.New("dmidecode unavailable")
	m.diskErr = errors.New("sysfs unavailable")
	m.nicErr = errors.New("net unavailable")
	m.hwErr = errors.New("dmi unavailable")
	c := collector.NewInfoCollectorWithReader(m, collector.InfoConfig{})
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect must not return error: %v", err)
	}
	// Original 5 metrics must still be present.
	names := make(map[string]bool, len(pts))
	for _, p := range pts {
		names[p.Name] = true
	}
	for _, want := range []string{"system_info", "cpu_info", "kernelcare_info"} {
		if !names[want] {
			t.Errorf("existing metric %q missing after new reader failures", want)
		}
	}
	// New metrics must be absent.
	for _, absent := range []string{"memory_hardware_info", "memory_module_info", "disk_hardware_info", "network_hardware_info", "hardware_info"} {
		if names[absent] {
			t.Errorf("metric %q should not be emitted when reader fails", absent)
		}
	}
}

func TestInfoCollector_MemoryTotalWithoutModules(t *testing.T) {
	m := newFullMock()
	m.memInfo = &collector.MemoryInfo{TotalMB: 16384, Modules: nil}
	c := collector.NewInfoCollectorWithReader(m, collector.InfoConfig{})
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	summaryCount := 0
	moduleCount := 0
	for _, p := range pts {
		switch p.Name {
		case "memory_hardware_info":
			summaryCount++
			if p.Labels["total_mb"] != "16384" {
				t.Errorf("total_mb = %q, want %q", p.Labels["total_mb"], "16384")
			}
		case "memory_module_info":
			moduleCount++
		}
	}
	if summaryCount != 1 {
		t.Errorf("expected 1 memory_hardware_info point, got %d", summaryCount)
	}
	if moduleCount != 0 {
		t.Errorf("expected 0 memory_module_info points when modules unavailable, got %d", moduleCount)
	}
}
