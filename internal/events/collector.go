package events

import "context"

// EventCollector is implemented by each event source domain.
// Run blocks until ctx is cancelled, sending collected events to out.
// It must not close out — the Pipeline owns the channel lifetime.
// Returning a non-nil error is treated as a fatal collector failure and logged.
// Collectors should return nil when ctx is cancelled.
type EventCollector interface {
	Name() string
	Run(ctx context.Context, out chan<- Event) error
}
