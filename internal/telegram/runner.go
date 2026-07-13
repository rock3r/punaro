package telegram

import (
	"context"
	"fmt"
)

// Poller retrieves a bounded ordered page of Telegram updates.
type Poller interface {
	Updates(context.Context, int64) ([]Update, error)
}

// Runner combines polling with the durable gateway policy. Its returned offset
// is advisory process state: processed update IDs remain the crash-safe source
// of truth, so replay is harmless.
type Runner struct {
	Poller  Poller
	Gateway Gateway
}

// RunOnce handles one update page and returns the next advisory offset.
func (r Runner) RunOnce(ctx context.Context, offset int64) (int64, error) {
	if r.Poller == nil {
		return offset, fmt.Errorf("telegram poller is required")
	}
	updates, err := r.Poller.Updates(ctx, offset)
	if err != nil {
		return offset, err
	}
	next := offset
	for _, update := range updates {
		if err := r.Gateway.Handle(ctx, update); err != nil {
			return offset, err
		}
		if update.ID >= next {
			next = update.ID + 1
		}
	}
	return next, nil
}
