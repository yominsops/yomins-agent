package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yominsops/yomins-agent/internal/smart"
)

// runSmartScan reads all disks with smartctl and writes the report the
// agent's SMART collector reads. yomins-agent-smart.timer runs it as root.
func runSmartScan(args []string) error {
	fs := flag.NewFlagSet("smart-scan", flag.ContinueOnError)
	out := fs.String("out", smart.DefaultReportPath, "where to write the report")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	r := smart.Scan(ctx, nil)
	if err := smart.Write(*out, r); err != nil {
		return fmt.Errorf("write %s: %w", *out, err)
	}
	switch {
	case !r.Smartctl:
		fmt.Fprintln(os.Stderr, "smart-scan: smartctl not found (install smartmontools); report written")
	case r.Error != "":
		fmt.Fprintf(os.Stderr, "smart-scan: %s\n", r.Error)
	default:
		fmt.Fprintf(os.Stderr, "smart-scan: %d disk(s) read\n", len(r.Devices))
	}
	return nil
}
