// Package smart reads disk health (SMART) with smartctl. Reading SMART needs
// root (raw ATA commands, NVMe admin commands), which the agent does not
// have, so `yomins-agent smart-scan` runs from its own root timer
// (yomins-agent-smart.timer), writes a report next to the agent's state, and
// the unprivileged agent turns the report into metrics.
package smart

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ReportVersion changes when the report format does.
const ReportVersion = 1

// DefaultReportPath is where the timer writes the report.
const DefaultReportPath = "/var/lib/yomins/agent/smart.json"

// Report is one scan of all disks.
type Report struct {
	Version  int       `json:"version"`
	Time     time.Time `json:"time"`
	Smartctl bool      `json:"smartctl"` // false: smartmontools is not installed
	Error    string    `json:"error,omitempty"`
	Devices  []Device  `json:"devices"`
}

// Device is one disk. Attributes hold the counters that predict a failure,
// by a stable name (see attributeNames and the nvme_* keys).
type Device struct {
	Name         string             `json:"name"`
	Type         string             `json:"type"`
	Protocol     string             `json:"protocol"`
	Model        string             `json:"model,omitempty"`
	Serial       string             `json:"serial,omitempty"`
	Standby      bool               `json:"standby,omitempty"` // asleep: not woken up to be read
	Healthy      *bool              `json:"healthy,omitempty"` // the drive's own verdict
	TemperatureC *float64           `json:"temperature_c,omitempty"`
	PowerOnHours *float64           `json:"power_on_hours,omitempty"`
	Attributes   map[string]float64 `json:"attributes,omitempty"`
}

// attributeNames are the ATA attributes worth watching, by ID: the ones
// Backblaze's drive statistics link to failures, and cable errors.
var attributeNames = map[int]string{
	5:   "reallocated_sectors",
	187: "reported_uncorrectable",
	188: "command_timeouts",
	197: "pending_sectors",
	198: "offline_uncorrectable",
	199: "udma_crc_errors",
}

// Runner runs a command and returns its stdout and exit code.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, int, error)

func execRunner(ctx context.Context, name string, args ...string) ([]byte, int, error) {
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if ee, ok := err.(*exec.ExitError); ok {
		return out, ee.ExitCode(), nil
	}
	if err != nil {
		return out, -1, err
	}
	return out, 0, nil
}

type scanOutput struct {
	Devices []struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Protocol string `json:"protocol"`
	} `json:"devices"`
}

type deviceOutput struct {
	ModelName    string `json:"model_name"`
	ModelFamily  string `json:"model_family"`
	ScsiModel    string `json:"scsi_model_name"`
	SerialNumber string `json:"serial_number"`
	Device       struct {
		Protocol string `json:"protocol"`
	} `json:"device"`
	SmartSupport *struct {
		Available bool `json:"available"`
		Enabled   bool `json:"enabled"`
	} `json:"smart_support"`
	SmartStatus *struct {
		Passed bool `json:"passed"`
	} `json:"smart_status"`
	Temperature *struct {
		Current float64 `json:"current"`
	} `json:"temperature"`
	PowerOnTime *struct {
		Hours float64 `json:"hours"`
	} `json:"power_on_time"`
	ATA *struct {
		Table []struct {
			ID         int    `json:"id"`
			WhenFailed string `json:"when_failed"`
			Raw        struct {
				Value float64 `json:"value"`
			} `json:"raw"`
		} `json:"table"`
	} `json:"ata_smart_attributes"`
	NVMe *struct {
		CriticalWarning   float64 `json:"critical_warning"`
		AvailableSpare    float64 `json:"available_spare"`
		AvailableSpareThr float64 `json:"available_spare_threshold"`
		PercentageUsed    float64 `json:"percentage_used"`
		MediaErrors       float64 `json:"media_errors"`
		ErrorLogEntries   float64 `json:"num_err_log_entries"`
		UnsafeShutdowns   float64 `json:"unsafe_shutdowns"`
	} `json:"nvme_smart_health_information_log"`
	ScsiGrownDefects *float64 `json:"scsi_grown_defect_list"`
}

// Exit status bits of smartctl (man smartctl, EXIT STATUS): bit 0 is a
// command line error, bit 1 a device that could not be opened or is in a
// low-power mode (-n standby). The other bits describe the disk, not the run.
const (
	exitCmdLine = 1 << 0
	exitOpen    = 1 << 1
)

// Scan reads every disk smartctl finds. Disks that sleep are left asleep.
func Scan(ctx context.Context, run Runner) Report {
	r := Report{Version: ReportVersion, Time: time.Now().UTC(), Devices: []Device{}}
	if run == nil {
		if _, err := exec.LookPath("smartctl"); err != nil {
			return r // smartmontools is not installed
		}
		run = execRunner
	}
	r.Smartctl = true
	out, code, err := run(ctx, "smartctl", "--scan-open", "--json")
	if err != nil {
		r.Error = err.Error()
		return r
	}
	var scan scanOutput
	if err := json.Unmarshal(out, &scan); err != nil {
		r.Error = fmt.Sprintf("smartctl --scan-open: exit %d: %v", code, err)
		return r
	}
	for _, d := range scan.Devices {
		if !strings.HasPrefix(d.Name, "/dev/") || strings.ContainsAny(d.Type, " \t\n") {
			continue
		}
		if dev, ok := scanDevice(ctx, run, d.Name, d.Type, d.Protocol); ok {
			r.Devices = append(r.Devices, dev)
		}
	}
	return r
}

func scanDevice(ctx context.Context, run Runner, name, typ, protocol string) (Device, bool) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	args := []string{"--json", "--all", "--nocheck=standby"}
	if typ != "" {
		args = append(args, "--device="+typ)
	}
	out, code, err := run(ctx, "smartctl", append(args, name)...)
	dev := Device{Name: name, Type: typ, Protocol: protocol}
	if err != nil || code&exitCmdLine != 0 {
		return dev, false
	}
	var o deviceOutput
	if json.Unmarshal(out, &o) != nil {
		return dev, false
	}
	if o.Device.Protocol != "" {
		dev.Protocol = o.Device.Protocol
	}
	dev.Model = firstNonEmpty(o.ModelName, o.ScsiModel, o.ModelFamily)
	dev.Serial = o.SerialNumber
	if code&exitOpen != 0 {
		// Asleep (-n standby) or not openable. Report a sleeping disk so it
		// does not look gone; skip one that could not be read at all.
		// smartctl says so in its messages ("Device is in STANDBY mode").
		if up := strings.ToUpper(string(out)); strings.Contains(up, "STANDBY") || strings.Contains(up, "SLEEP") {
			dev.Standby = true
			return dev, true
		}
		return dev, false
	}
	if o.SmartSupport != nil && !o.SmartSupport.Available && o.NVMe == nil {
		return dev, false // a virtual disk, a USB bridge that hides SMART
	}
	if o.SmartStatus != nil {
		passed := o.SmartStatus.Passed
		dev.Healthy = &passed
	}
	if o.Temperature != nil && o.Temperature.Current > 0 {
		t := o.Temperature.Current
		dev.TemperatureC = &t
	}
	if o.PowerOnTime != nil {
		h := o.PowerOnTime.Hours
		dev.PowerOnHours = &h
	}
	attrs := map[string]float64{}
	if o.ATA != nil {
		failing := 0
		for _, a := range o.ATA.Table {
			if n, ok := attributeNames[a.ID]; ok {
				attrs[n] = a.Raw.Value
			}
			if a.WhenFailed == "now" {
				failing++
			}
		}
		attrs["failing_now"] = float64(failing)
	}
	if n := o.NVMe; n != nil {
		attrs["nvme_critical_warning"] = n.CriticalWarning
		attrs["nvme_available_spare_percent"] = n.AvailableSpare
		attrs["nvme_available_spare_threshold_percent"] = n.AvailableSpareThr
		attrs["nvme_percentage_used"] = n.PercentageUsed
		attrs["nvme_media_errors"] = n.MediaErrors
		attrs["nvme_error_log_entries"] = n.ErrorLogEntries
		attrs["nvme_unsafe_shutdowns"] = n.UnsafeShutdowns
	}
	if o.ScsiGrownDefects != nil {
		attrs["scsi_grown_defects"] = *o.ScsiGrownDefects
	}
	if len(attrs) > 0 {
		dev.Attributes = attrs
	}
	return dev, true
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

// Write saves the report atomically, readable by the agent.
func Write(path string, r Report) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".smart-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Read loads a report.
func Read(path string) (Report, error) {
	var r Report
	b, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, err
	}
	if r.Version != ReportVersion {
		return r, fmt.Errorf("smart report version %d, want %d", r.Version, ReportVersion)
	}
	return r, nil
}
