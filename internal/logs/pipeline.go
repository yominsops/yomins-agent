package logs

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Source produces entries until its context is done.
type Source interface {
	Name() string
	Run(ctx context.Context, out chan<- Entry) error
}

// Pipeline runs the sources into one shipper and saves positions regularly.
type Pipeline struct {
	sources   []Source
	shipper   *Shipper
	positions *Positions
}

// NewPipeline wires sources to a shipper.
func NewPipeline(sources []Source, shipper *Shipper, positions *Positions) *Pipeline {
	return &Pipeline{sources: sources, shipper: shipper, positions: positions}
}

// Run blocks until ctx is done, then saves the positions a last time.
func (p *Pipeline) Run(ctx context.Context) {
	ch := make(chan Entry, 1000)
	var wg sync.WaitGroup
	for _, s := range p.sources {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.Run(ctx, ch); err != nil {
				slog.Error("logs: source stopped", "source", s.Name(), "error", err)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.shipper.Run(ctx, ch)
	}()

	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			p.save()
			return
		case <-t.C:
			p.save()
		}
	}
}

func (p *Pipeline) save() {
	if err := p.positions.Save(); err != nil {
		slog.Warn("logs: cannot save positions", "error", err)
	}
}
