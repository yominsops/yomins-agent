package main

import (
	"context"
	"flag"
	"os/signal"
	"syscall"

	"github.com/yominsops/yomins-agent/internal/jobs"
)

// runJobRun is `yomins-agent job-run`: run as root by yomins-agent-jobs.service
// when a job arrives in the inbox. It checks each job's signature against the key
// pinned at install and runs yopatch; no config, no network. The flags (for a
// manual test) default to the installed paths.
func runJobRun(args []string) error {
	p := jobs.DefaultPaths
	fs := flag.NewFlagSet("job-run", flag.ContinueOnError)
	fs.StringVar(&p.StateDir, "state", p.StateDir, "the agent's state directory (agent_id, jobs/)")
	fs.StringVar(&p.PublicKey, "key", p.PublicKey, "the job key (PEM, P-256)")
	fs.StringVar(&p.Seen, "seen", p.Seen, "where jobs already taken are remembered")
	fs.StringVar(&p.Yopatch, "yopatch", p.Yopatch, "the yopatch script")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return (&jobs.Runner{Paths: p}).RunAll(ctx)
}
