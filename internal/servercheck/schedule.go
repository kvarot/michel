package servercheck

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// retryAfter is how long the scheduler waits before trying again a server
// whose check failed (its check date does not move on a failure).
const retryAfter = time.Hour

// Scheduler checks the due servers (target.Repo.Due), one at a time, now and
// then every `every`, until ctx ends. A failed check is logged without what
// the server printed and tried again after retryAfter at the earliest.
func Scheduler(ctx context.Context, d CheckDeps, every time.Duration) {
	if every <= 0 {
		every = time.Minute
	}
	failed := map[string]time.Time{}
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		runDue(ctx, d, failed)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func runDue(ctx context.Context, d CheckDeps, failed map[string]time.Time) {
	now := d.now()
	due, err := d.Repo.Due(ctx, now)
	if err != nil {
		if ctx.Err() == nil {
			slog.Warn("servercheck: cannot list the servers to check", "err", err)
		}
		return
	}
	for _, t := range due {
		if ctx.Err() != nil {
			return
		}
		if at, ok := failed[t.ID]; ok && now.Sub(at) < retryAfter {
			continue
		}
		if _, err := Check(ctx, d, t.ID); err != nil {
			if errors.Is(err, context.Canceled) || ctx.Err() != nil {
				return
			}
			failed[t.ID] = now
			slog.Warn("servercheck: the check of a server failed", "target", t.ID, "err", err)
			continue
		}
		delete(failed, t.ID)
	}
}
