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

// SweepRunning ends the server fixes left running past their own bound
// (the deadline stored when the run was claimed) plus a margin: their
// process stopped, the script may have run in part or whole. Each one
// becomes unknown (never a guessed undo), then an urgent alert asks to look
// at the server and the server is checked again. A run still within its
// bound is left alone: another process may be running it. It returns how
// many were ended.
func SweepRunning(ctx context.Context, d Deps) (int, error) {
	repo := d.repo()
	// A record without a deadline (claimed before the deadline existed)
	// counts from its claim with the longest default bound.
	stale, err := repo.StaleRunning(ctx, d.now().Add(-runningMargin), DefaultPackageApplyTimeout)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, a := range stale {
		if err := repo.SetState(ctx, a.ID, []State{StateRunning}, StateUnknown, i18n.T(d.lang(), "fix.server.unknown_state")); err != nil {
			// Moved meanwhile (the run ended after all): nothing to say.
			continue
		}
		n++
		_ = keep("server_fix.apply", a.ID, d.record(ctx, "server_fix.apply", a.ID, "error",
			map[string]any{"attempt_id": a.ID, "target_id": a.ProjectID, "error": "fix.server.unknown_state", "reason": "left running"}))
		post, cancel := context.WithTimeout(context.WithoutCancel(ctx), d.recordTimeout())
		if d.Targets != nil {
			if t, err := d.Targets.Get(post, a.ProjectID); err == nil {
				d.alert(post, servercheck.AlertInput{Target: t, Kind: servercheck.AlertUnknownState, Urgent: true})
			}
		}
		if d.CheckServer != nil {
			if _, err := d.CheckServer(post, a.ProjectID); err != nil {
				keep("recollect", a.ID, err)
			}
		}
		cancel()
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
