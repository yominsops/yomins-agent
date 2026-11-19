package smart

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

const scanJSON = `{"json_format_version":[1,0],"smartctl":{"exit_status":0},
"devices":[
 {"name":"/dev/sda","info_name":"/dev/sda [SAT]","type":"sat","protocol":"ATA"},
 {"name":"/dev/sdb","info_name":"/dev/sdb [SAT]","type":"sat","protocol":"ATA"},
 {"name":"/dev/nvme0","info_name":"/dev/nvme0","type":"nvme","protocol":"NVMe"},
 {"name":"/dev/bus/0","info_name":"/dev/bus/0 [megaraid_disk_00]","type":"megaraid,0","protocol":"SCSI"},
 {"name":"/dev/sdc","info_name":"/dev/sdc","type":"scsi","protocol":"SCSI"},
 {"name":"; rm -rf /","type":"sat"}
]}`

const sdaJSON = `{"smartctl":{"exit_status":0},"device":{"name":"/dev/sda","type":"sat","protocol":"ATA"},
"model_name":"ST4000NM0035-1V4107","serial_number":"ZC1A2B3C",
"smart_support":{"available":true,"enabled":true},"smart_status":{"passed":true},
"power_on_time":{"hours":41234},"temperature":{"current":34},
"ata_smart_attributes":{"table":[
 {"id":5,"name":"Reallocated_Sector_Ct","value":100,"worst":100,"thresh":10,"when_failed":"","raw":{"value":8,"string":"8"}},
 {"id":9,"name":"Power_On_Hours","value":53,"raw":{"value":41234}},
 {"id":197,"name":"Current_Pending_Sector","value":100,"when_failed":"","raw":{"value":2}},
 {"id":198,"name":"Offline_Uncorrectable","value":100,"when_failed":"","raw":{"value":0}},
 {"id":199,"name":"UDMA_CRC_Error_Count","value":200,"when_failed":"","raw":{"value":0}}
]}}`

// Failing drive: smartctl sets bit 3 (DISK FAILING), which is not a run error.
const sdbJSON = `{"smartctl":{"exit_status":8},"device":{"protocol":"ATA"},"model_name":"WDC WD10EZEX",
"serial_number":"WD-1","smart_support":{"available":true,"enabled":true},"smart_status":{"passed":false},
"ata_smart_attributes":{"table":[{"id":5,"when_failed":"now","raw":{"value":4012}}]}}`

const nvmeJSON = `{"smartctl":{"exit_status":0},"device":{"protocol":"NVMe"},"model_name":"SAMSUNG MZQL2960HCJR-00A07",
"serial_number":"S64FNE0R","smart_status":{"passed":true},"temperature":{"current":41},"power_on_time":{"hours":9000},
"nvme_smart_health_information_log":{"critical_warning":0,"temperature":41,"available_spare":100,"available_spare_threshold":10,
"percentage_used":7,"media_errors":0,"num_err_log_entries":12,"unsafe_shutdowns":31}}`

const megaraidJSON = `{"smartctl":{"exit_status":0},"device":{"protocol":"SCSI"},"scsi_model_name":"SEAGATE ST600MM0006",
"serial_number":"S0M1","smart_status":{"passed":true},"temperature":{"current":30},"scsi_grown_defect_list":3}`

// Asleep: -n standby makes smartctl exit with bit 1 set.
const sdcJSON = `{"smartctl":{"exit_status":2},"device":{"protocol":"ATA"},"smartctl_messages":[{"string":"Device is in STANDBY mode, exit(2)","severity":"information"}]}`

func fakeRun(t *testing.T, calls *[]string) Runner {
	return func(_ context.Context, name string, args ...string) ([]byte, int, error) {
		*calls = append(*calls, name+" "+strings.Join(args, " "))
		if args[0] == "--scan-open" {
			return []byte(scanJSON), 0, nil
		}
		switch args[len(args)-1] {
		case "/dev/sda":
			return []byte(sdaJSON), 0, nil
		case "/dev/sdb":
			return []byte(sdbJSON), 8, nil
		case "/dev/nvme0":
			return []byte(nvmeJSON), 0, nil
		case "/dev/bus/0":
			return []byte(megaraidJSON), 0, nil
		case "/dev/sdc":
			return []byte(sdcJSON), 2, nil
		}
		t.Fatalf("unexpected device %v", args)
		return nil, 0, nil
	}
}

func TestScan(t *testing.T) {
	var calls []string
	r := Scan(context.Background(), fakeRun(t, &calls))
	if !r.Smartctl || r.Error != "" {
		t.Fatalf("report: %+v", r)
	}
	if len(r.Devices) != 5 {
		t.Fatalf("devices = %d, want 5 (the bogus name skipped): %+v", len(r.Devices), r.Devices)
	}
	by := map[string]Device{}
	for _, d := range r.Devices {
		by[d.Name] = d
	}
	sda := by["/dev/sda"]
	if sda.Model != "ST4000NM0035-1V4107" || *sda.Healthy != true || *sda.TemperatureC != 34 || *sda.PowerOnHours != 41234 {
		t.Errorf("sda: %+v", sda)
	}
	if sda.Attributes["reallocated_sectors"] != 8 || sda.Attributes["pending_sectors"] != 2 || sda.Attributes["failing_now"] != 0 {
		t.Errorf("sda attributes: %v", sda.Attributes)
	}
	if sdb := by["/dev/sdb"]; *sdb.Healthy || sdb.Attributes["failing_now"] != 1 || sdb.Attributes["reallocated_sectors"] != 4012 {
		t.Errorf("sdb: %+v", sdb)
	}
	if n := by["/dev/nvme0"]; n.Attributes["nvme_percentage_used"] != 7 || n.Attributes["nvme_error_log_entries"] != 12 {
		t.Errorf("nvme: %+v", n)
	}
	if m := by["/dev/bus/0"]; m.Type != "megaraid,0" || m.Model != "SEAGATE ST600MM0006" || m.Attributes["scsi_grown_defects"] != 3 {
		t.Errorf("megaraid: %+v", m)
	}
	if c := by["/dev/sdc"]; !c.Standby || c.Healthy != nil {
		t.Errorf("sdc: %+v", c)
	}
	for _, c := range calls {
		if strings.Contains(c, "/dev/sd") && !strings.Contains(c, "--nocheck=standby") {
			t.Errorf("would wake a sleeping disk: %s", c)
		}
	}
}

func TestWriteRead(t *testing.T) {
	var calls []string
	path := filepath.Join(t.TempDir(), "smart.json")
	if err := Write(path, Scan(context.Background(), fakeRun(t, &calls))); err != nil {
		t.Fatal(err)
	}
	r, err := Read(path)
	if err != nil || len(r.Devices) != 5 {
		t.Fatalf("read: %v %+v", err, r)
	}
}
