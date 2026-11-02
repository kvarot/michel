package servercheck

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/kvarot/michel/internal/sshx"
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
			slog.Warn("servercheck: the check of a server failed", "target", t.ID, "name", t.Name, "reason", reasonOf(err))
			continue
		}
		delete(failed, t.ID)
	}
}

// reasonOf names why a check failed, without its text (which can carry the
// SSH user and the host).
func reasonOf(err error) string {
	var unk sshx.ErrHostKeyUnknown
	var chg sshx.ErrHostKeyChanged
	switch {
	case errors.As(err, &chg):
		return "host_key_changed"
	case errors.As(err, &unk):
		return "host_key_unknown"
	case errors.Is(err, sshx.ErrDenied):
		return "denied"
	case errors.Is(err, sshx.ErrNoAgent):
		return "no_agent"
	case errors.Is(err, sshx.ErrNoKeyAccepted):
		return "no_key_accepted"
	case errors.Is(err, sshx.ErrCommandTimeout), errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, ErrInactive):
		return "inactive"
	}
	return "error"
}
