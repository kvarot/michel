package fix

import (
	"context"
	"time"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/servercheck"
)

// RunningSweepInterval is how often michel serve looks for server fixes
// left running by a process that stopped.
const RunningSweepInterval = 5 * time.Minute

// appliedMargin is how long after its run's bound a server fix may stay
// applied (site check, recollection, undo and recording, each bounded)
// before a sweeper takes its process for stopped.
const appliedMargin = 30 * time.Minute

// SweepRunning ends the server fixes a stopped process left half way:
// running past their own bound (the deadline stored when the run was
// claimed) plus runningMargin, or applied past it plus appliedMargin (the
// steps after the script never ended). The script may have run in part or
// whole: each one becomes unknown (never a guessed undo), then an urgent
// alert asks to look at the server and the server is checked again, each
// step under its own bound. A run still within its bound is left alone:
// another process may be running it. A code fix (applied is final there)
// is never touched. It returns how many were ended.
func SweepRunning(ctx context.Context, d Deps) (int, error) {
	repo := d.repo()
	ends, err := repo.RunEnds(ctx)
	if err != nil {
		return 0, err
	}
	now := d.now()
	n := 0
	for _, e := range ends {
		a := e.Attempt
		if a.Work.Server == nil {
			continue
		}
		end := e.Deadline
		if end.IsZero() {
			// A record without a deadline (AppliedByMe, or claimed before
			// deadlines were stored) counts from its last change.
			end = a.UpdatedAt.Add(DefaultPackageApplyTimeout)
		}
		margin := runningMargin
		if a.State == StateApplied {
			margin = appliedMargin
		}
		if !now.After(end.Add(margin)) {
			continue
		}
		if err := repo.SetState(ctx, a.ID, []State{a.State}, StateUnknown, i18n.T(d.lang(), "fix.server.unknown_state")); err != nil {
			// Moved meanwhile (the run ended after all): nothing to say.
			continue
		}
		n++
		base := context.WithoutCancel(ctx)
		step := func(bound time.Duration, f func(context.Context)) {
			c, cancel := context.WithTimeout(base, bound)
			defer cancel()
			f(c)
		}
		step(d.recordTimeout(), func(c context.Context) {
			_ = keep("server_fix.apply", a.ID, d.record(c, "server_fix.apply", a.ID, "error",
				map[string]any{"attempt_id": a.ID, "target_id": a.ProjectID, "error": "fix.server.unknown_state", "reason": "left " + string(a.State)}))
		})
		if d.Targets != nil {
			step(d.recordTimeout(), func(c context.Context) {
				if t, err := d.Targets.Get(c, a.ProjectID); err == nil {
					d.alert(c, servercheck.AlertInput{Target: t, Kind: servercheck.AlertUnknownState, Urgent: true})
				}
			})
		}
		if d.CheckServer != nil {
			step(d.checkTimeout(), func(c context.Context) {
				if _, err := d.CheckServer(c, a.ProjectID); err != nil {
					keep("recollect", a.ID, err)
				}
			})
		}
	}
	return n, nil
}

// RunningSweeper calls SweepRunning every interval until ctx ends (michel
// serve).
func RunningSweeper(ctx context.Context, d Deps, interval time.Duration) {
	if interval <= 0 {
		interval = RunningSweepInterval
	}
	tk := time.NewTicker(interval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			if _, err := SweepRunning(ctx, d); err != nil {
				keep("sweep running", "", err)
			}
		}
	}
}
