package watch

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
)

// Retries of a failed check: at most MaxRetries more tries in the day,
// RetryAfter apart. In memory, as the retries of the digest. After a restart
// of serve, a project whose check of the day failed and was recorded as
// failed waits for tomorrow (its failed scan counts); one whose failure left
// no scan (no database) is tried once more at each restart, never in a loop;
// one whose check was interrupted, or left running by a crash, is checked
// again.
const (
	MaxRetries = 2
	RetryAfter = 30 * time.Minute
)

// Deps are the collaborators of Loop.
type Deps struct {
	Now func() time.Time
	// Policy is the policy in force, read at each look: a change of
	// watch.scan_at counts from the next look.
	Policy func() policy.Policy
	// Projects lists the projects (active or not).
	Projects func(ctx context.Context) ([]project.Project, error)
	Repo     *Repo
	// Sources reads the enabled sources, as michel source update; its error
	// is a warning, the offline checks go on.
	Sources func(ctx context.Context) error
	// Scan checks one project as michel scan does. nil and an error wrapping
	// scan.ErrScanRunning (another process checks it) are not failures; any
	// other error is, and is tried again.
	Scan func(ctx context.Context, p project.Project) error
	// Log receives the warnings; nil is slog's default.
	Log *slog.Logger
	// TickHook, when set (tests), is called at the end of each look.
	TickHook func()
}

// try is how the watch of the day went for one project, in this process.
type try struct {
	n    int
	done bool
	next time.Time
}

// Loop runs the daily watch until ctx ends: it looks at once, then every
// `every`. A look reads the sources once a day (the first look past the hour),
// then checks the due projects one after the other. Stopping ctx stops the
// check in progress (scan.Run is cancellable) and starts no other.
func Loop(ctx context.Context, d Deps, every time.Duration) {
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	window, tries := "", map[string]*try{}
	look := func() {
		h, m, on := d.Policy().WatchHour()
		if !on {
			return
		}
		now := d.Now()
		start := DayStart(now, h, m)
		if now.Before(start) {
			return
		}
		// The tries are those of this hour of this day: a new day, or a new
		// hour in the policy, starts again from the database.
		if key := start.Format(time.RFC3339); key != window {
			window, tries = key, map[string]*try{}
			claimed, err := d.Repo.ClaimSources(ctx, start.Format("2006-01-02"), now)
			switch {
			case err != nil:
				if ctx.Err() == nil {
					log.Warn("serve: the daily watch cannot record its source read; the sources are not read today", "err", err)
				}
			case claimed:
				if err := d.Sources(ctx); err != nil && ctx.Err() == nil {
					log.Warn("serve: the daily watch could not read every source; the checks go on with the data already here", "err", err)
				}
			}
		}
		if ctx.Err() != nil {
			return
		}
		list, err := d.Projects(ctx)
		if err != nil {
			if ctx.Err() == nil {
				log.Warn("serve: the daily watch cannot read the projects", "err", err)
			}
			return
		}
		last, err := d.Repo.LastStarts(ctx)
		if err != nil {
			if ctx.Err() == nil {
				log.Warn("serve: the daily watch cannot read the last checks", "err", err)
			}
			return
		}
		for _, p := range list {
			if ctx.Err() != nil {
				return
			}
			if !p.Active || !p.AutoScan {
				continue
			}
			t := tries[p.ID]
			now := d.Now()
			if t != nil {
				if t.done || t.n > MaxRetries || now.Before(t.next) {
					continue
				}
			} else {
				at, has := last[p.ID]
				if !Due(at, has, now, h, m) {
					continue
				}
				t = &try{}
				tries[p.ID] = t
			}
			err := d.Scan(ctx, p)
			if ctx.Err() != nil {
				return
			}
			t.n++
			switch {
			case err == nil, errors.Is(err, scan.ErrScanRunning):
				t.done = true
			default:
				t.next = d.Now().Add(RetryAfter)
				if t.n > MaxRetries {
					log.Warn("serve: the daily watch could not check a project; it tries again tomorrow", "project", p.Name)
				} else {
					log.Warn("serve: the daily watch could not check a project; it tries again in 30 minutes", "project", p.Name)
				}
			}
		}
	}
	tick := func() {
		look()
		if d.TickHook != nil {
			d.TickHook()
		}
	}
	tick()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}
