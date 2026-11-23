package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/yominsops/yomins-agent/internal/restartscan"
)

// runRestartScan is `yomins-agent restart-scan`: run as root by
// yomins-agent-restart.timer, it looks for services still running code an
// update replaced and writes the report the agent reads. No config, no
// network.
func runRestartScan(args []string) error {
	fs := flag.NewFlagSet("restart-scan", flag.ContinueOnError)
	out := fs.String("out", restartscan.DefaultReportPath, "where to write the report")
	proc := fs.String("proc", "/proc", "the proc filesystem to read")
	if err := fs.Parse(args); err != nil {
		return err
	}
	r := restartscan.Scan(*proc)
	if err := restartscan.Write(*out, r); err != nil {
		return fmt.Errorf("write %s: %w", *out, err)
	}
	if r.Error != "" {
		fmt.Fprintf(os.Stderr, "restart-scan: %s\n", r.Error)
	} else {
		fmt.Fprintf(os.Stderr, "restart-scan: %d service(s) need a restart\n", len(r.Units))
	}
	return nil
}
