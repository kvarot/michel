package fix

import (
	"context"
	"errors"
	"time"

	"github.com/kvarot/michel/internal/decide"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
)

// Eligible reports whether a finding is one Michel prepares a fix for by
// itself (fix level 2): an open dependency finding (new, pending, or
// decided "fix"), never deferred nor ignored, with a known fixed version,
// on an active project at level 2 or more. decided gives the action of the
// decision in force ("" when none). Attempts in progress and refused
// proposals are checked by the worker, not here.
func Eligible(f scan.Finding, p project.Project, decided func(id string) string) bool {
	if !p.Active || p.FixLevel < 2 {
		return false
	}
	if f.Kind != "" && f.Kind != scan.KindDependency {
		return false
	}
	if len(f.FixedVersions) == 0 {
		return false
	}
	action := ""
	if decided != nil {
		action = decided(f.ID)
	}
	switch f.Status {
	case scan.StatusNew, scan.StatusPending:
		return action != string(decide.Defer) && action != string(decide.Ignore)
	case scan.StatusDecided:
		return action == string(decide.Fix)
	}
	return false
}

// QueueEligible puts the eligible findings of the project in the queue of
// automatic attempts and returns how many it queued. A project below level
// 2 or without AI consent queues nothing (Michel stays at level 1 and the
// page says so).
func QueueEligible(ctx context.Context, d Deps, projectID string) (int, error) {
	p, err := project.NewRepo(d.Store).Get(ctx, projectID)
	if err != nil {
		return 0, err
	}
	if p.FixLevel < 2 || !p.Active {
		return 0, nil
	}
	if ok, err := d.consentOK(ctx, p); err != nil || !ok {
		return 0, err
	}
	findings, err := scan.NewRepo(d.Store).ListFindings(ctx, p.ID, "")
	if err != nil {
		return 0, err
	}
	current, err := decide.NewRepo(d.Store).CurrentByProject(ctx, p.ID)
	if err != nil {
		return 0, err
	}
	decided := func(id string) string {
		if dec, ok := current[id]; ok {
			return string(dec.Action)
		}
		return ""
	}
	repo := d.repo()
	n := 0
	for _, f := range findings {
		if !Eligible(f, p, decided) {
			continue
		}
		if skip, err := d.alreadyTried(ctx, f); err != nil {
			return n, err
		} else if skip {
			continue
		}
		if err := repo.Enqueue(ctx, f.ID, p.ID); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// alreadyTried reports whether an attempt is in progress for the finding
// or a proposal for the same fixed version was refused.
func (d Deps) alreadyTried(ctx context.Context, f scan.Finding) (bool, error) {
	attempts, err := d.repo().AttemptsOf(ctx, f.ID)
	if err != nil {
		return false, err
	}
	target := ""
	if len(f.FixedVersions) > 0 {
		target = f.FixedVersions[0]
	}
	for _, a := range attempts {
		switch a.State {
		case StatePreparing, StateProposed, StateApproved, StateApplied:
			return true, nil
		case StateRefused:
			if a.Work.Plan.Target == target {
				return true, nil
			}
		}
	}
	return false, nil
}

// WorkOnce takes the next queued finding whose project is free and under
// its daily cap (MaxAutoPerDay attempts started alone), checks it is still
// eligible and starts an attempt for it (origin agent.claude.auto). It
// reports whether an attempt was started. A finding no longer eligible is
// dropped; a project at its cap keeps its findings for tomorrow; a refusal
// of Start (consent withdrawn, agent gone...) is audited and the finding
// dropped. The pop and the creation happen in this one goroutine, in order.
func WorkOnce(ctx context.Context, d Deps) (bool, error) {
	repo := d.repo()
	var capped []string
	for {
		findingID, projectID, ok, err := repo.NextQueued(ctx, capped...)
		if err != nil || !ok {
			return false, err
		}
		n, err := repo.StartedToday(ctx, projectID, d.now())
		if err != nil {
			return false, err
		}
		if n >= MaxAutoPerDay {
			if err := repo.Enqueue(ctx, findingID, projectID); err != nil {
				return false, err
			}
			capped = append(capped, projectID)
			continue
		}
		f, p, err := d.find(ctx, findingID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				continue
			}
			return false, err
		}
		dec, has, err := decide.NewRepo(d.Store).Current(ctx, f.ID)
		if err != nil {
			return false, err
		}
		decided := func(string) string {
			if has {
				return string(dec.Action)
			}
			return ""
		}
		if !Eligible(f, p, decided) {
			continue
		}
		if skip, err := d.alreadyTried(ctx, f); err != nil {
			return false, err
		} else if skip {
			continue
		}
		auto := d
		auto.Actor = "serve"
		if _, err := Start(ctx, auto, f.ID, OriginAgentAuto); err != nil {
			if errors.Is(err, ErrBusy) {
				if err := repo.Enqueue(ctx, findingID, projectID); err != nil {
					return false, err
				}
				capped = append(capped, projectID)
				continue
			}
			if key := ErrorKey(err); key != "" {
				_ = d.record(ctx, "fix.start", f.ID, "refused", map[string]any{"finding_id": f.ID, "project_id": p.ID, "origin": OriginAgentAuto, "reason": key})
				continue
			}
			return false, err
		}
		return true, nil
	}
}

// Worker is the loop of michel serve: it looks at the queue every
// WorkerInterval, one attempt at a time, and purges the old messages once a
// day. It returns when ctx is done.
func Worker(ctx context.Context, d Deps) {
	interval := d.WorkerInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	lastPurge := d.now()
	for {
		if _, err := WorkOnce(ctx, d); err != nil {
			_ = d.record(ctx, "fix.worker", "serve", "error", map[string]any{"error": "worker_failed", "detail": auditDetail(d, err)})
		}
		if d.now().Sub(lastPurge) >= 24*time.Hour {
			_ = d.purge(ctx)
			lastPurge = d.now()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}
