package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/yominsops/yomins-agent/internal/inventory"
)

// runInventoryScan is `yomins-agent inventory-scan`: run as root once a day by
// yomins-agent-inventory.timer, it lists the software on the server and writes
// the report the agent sends. No config, no network.
func runInventoryScan(args []string) error {
	fs := flag.NewFlagSet("inventory-scan", flag.ContinueOnError)
	out := fs.String("out", inventory.DefaultReportPath, "where to write the report (- for stdout)")
	root := fs.String("root", "/", "the system to read (tests)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	r := inventory.Scan(ctx, &inventory.Env{Root: *root}, inventory.Detectors())
	if *out == "-" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}
	if err := inventory.Write(*out, r); err != nil {
		return fmt.Errorf("write %s: %w", *out, err)
	}
	fmt.Fprintf(os.Stderr, "inventory-scan: %d package(s), %d component(s)", len(r.Packages), len(r.Components))
	for d, e := range r.Errors {
		fmt.Fprintf(os.Stderr, "; %s: %s", d, e)
	}
	fmt.Fprintln(os.Stderr)
	return nil
}
