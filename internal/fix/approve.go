package fix

import (
	"context"
	"fmt"
	"strings"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/mask"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/workcopy"
)

// Approve records the user's approval of the current proposal of the
// attempt (state proposed): hash must be the proposal's (ErrStaleProposal
// otherwise, nothing changes). The actor is kept with the attempt.
func Approve(ctx context.Context, d Deps, attemptID, hash string) error {
	repo := d.repo()
	a, err := repo.GetAttempt(ctx, attemptID)
	if err != nil {
		return err
	}
	if a.State != StateProposed {
		return fmt.Errorf("%w (the attempt is %s)", ErrBadTransition, a.State)
	}
	prop, ok, err := repo.CurrentProposal(ctx, attemptID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNoProposal
	}
	if a.Work.Server != nil {
		return d.approveServer(ctx, a, prop, hash)
	}
	if hash == "" || prop.Hash != hash {
		_ = d.record(ctx, "fix.approve", attemptID, "refused", map[string]any{"attempt_id": attemptID, "reason": "stale proposal", "current_hash": prop.Hash})
		return ErrStaleProposal
	}
	if err := repo.Approve(ctx, attemptID, d.actor(), prop.ID, prop.Hash); err != nil {
		return err
	}
	return d.record(ctx, "fix.approve", attemptID, "ok", map[string]any{
		"attempt_id": attemptID, "finding_id": a.FindingID, "project_id": a.ProjectID, "proposal_id": prop.ID, "hash": prop.Hash, "author": d.actor(),
	})
}

// Apply creates the branch michel/fix-<id> in the user's repository from the
// approved proposal's commit (state approved): the agent's session is
// closed first, a patch holding a mask token is refused (ErrMaskToken, the
// attempt fails with Michel's cause), nothing else of the repository is touched. The
// attempt becomes applied; the copy, the mirror, the skill and the token
// go.
func Apply(ctx context.Context, d Deps, attemptID string) error {
	d.sessions().Close(attemptID)
	lock := d.sessions().attemptLock(attemptID)
	lock.Lock()
	defer lock.Unlock()
	a, err := d.repo().GetAttempt(ctx, attemptID)
	if err != nil {
		return err
	}
	if a.Work.Server != nil && a.State == StateRunning {
		return ErrBusy
	}
	if a.State != StateApproved {
		return fmt.Errorf("%w (the attempt is %s)", ErrBadTransition, a.State)
	}
	if a.Work.Server != nil {
		return d.applyServer(ctx, a)
	}
	return d.applyLocked(ctx, a)
}

func (d Deps) applyLocked(ctx context.Context, a Attempt) error {
	repo := d.repo()
	lang := d.lang()
	actor := d
	if a.ApprovedBy != "" {
		actor.Actor = a.ApprovedBy
	}
	prop, ok, err := repo.CurrentProposal(ctx, a.ID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNoProposal
	}
	// What was approved is what is applied: the current proposal must be
	// the one the approval named.
	if prop.ID != a.ApprovedProposal || prop.Hash != a.ApprovedHash || prop.Hash == "" {
		_ = actor.record(ctx, "fix.apply", a.ID, "refused", map[string]any{"attempt_id": a.ID, "reason": "proposal changed after approval", "approved_hash": a.ApprovedHash, "current_hash": prop.Hash})
		return ErrStaleProposal
	}
	branch := Branch(a.ID)
	// Only the raw patch, the bytes that reach the branch, is checked:
	// prop.Diff is the masked display copy and holds tokens by design
	// (final review C1). A refusal here is Michel's, not the user's: the
	// attempt fails with its cause (final review C3).
	if mask.HasToken(string(prop.DiffRaw)) {
		cause := i18n.T(lang, "fix.cause.apply_refused")
		if repo.SetState(ctx, a.ID, []State{StateApproved}, StateFailed, cause) == nil {
			_ = repo.SetCauseDetail(ctx, a.ID, auditDetail(d, ErrMaskToken))
		}
		_ = actor.record(ctx, "fix.apply", a.ID, "refused", map[string]any{"attempt_id": a.ID, "hash": prop.Hash, "reason": "mask token in the change"})
		d.cleanup(ctx, a, true)
		return ErrMaskToken
	}
	p, err := project.NewRepo(d.Store).Get(ctx, a.ProjectID)
	if err != nil {
		return err
	}
	if err := workcopy.Apply(ctx, d.work(), p, a.Work.Copy, prop.CommitSHA, branch); err != nil {
		_ = actor.record(ctx, "fix.apply", a.ID, "error", map[string]any{"attempt_id": a.ID, "hash": prop.Hash, "error": "apply_failed", "detail": auditDetail(d, err)})
		return err
	}
	if err := repo.SetState(ctx, a.ID, []State{StateApproved}, StateApplied, ""); err != nil {
		return err
	}
	_, _ = repo.AddMessage(ctx, Message{AttemptID: a.ID, Role: RoleMichel, Text: i18n.T(lang, "fix.msg.applied", branch)})
	if err := actor.record(ctx, "fix.apply", a.ID, "ok", map[string]any{
		"attempt_id": a.ID, "finding_id": a.FindingID, "project_id": a.ProjectID, "proposal_id": prop.ID, "hash": prop.Hash,
		"commit": prop.CommitSHA, "branch": branch, "files": len(prop.Files), "tests": prop.TestsStatus, "author": actor.actor(),
	}); err != nil {
		return err
	}
	d.cleanup(ctx, a, true)
	return nil
}

// Refuse ends the attempt (preparing, proposed or approved) on the user's
// decision, with an optional reason kept as its cause. The finding goes
// back to the decision circuit untouched: no decision is created. The
// session is closed, the copy, the skill and the token removed.
func Refuse(ctx context.Context, d Deps, attemptID, reason string) error {
	repo := d.repo()
	a, err := repo.GetAttempt(ctx, attemptID)
	if err != nil {
		return err
	}
	// Nothing was proposed to refuse: a held attempt ends as its "no" does.
	if a.State == StateHeld {
		return WithdrawHeld(ctx, d, attemptID)
	}
	if a.State != StatePreparing && a.State != StateProposed && a.State != StateApproved {
		return fmt.Errorf("%w (the attempt is %s)", ErrBadTransition, a.State)
	}
	reason = strings.TrimSpace(scan.SanitizeText(reason))
	if r, ok := d.sessions().get(attemptID); ok {
		reason = r.mask(d.Secrets, attemptID, reason)
	} else {
		// The session (if any) runs elsewhere and owns the saved table: a
		// fresh masker of its own nonce, never saved (final review I8).
		reason = mask.New().Mask(reason)
	}
	cause := reason
	if cause == "" {
		cause = i18n.T(d.lang(), "fix.cause.refused")
	}
	// The state first, under the attempt's lock: the end of a session that
	// is still running then finds the attempt refused and leaves it so
	// (closing the session first would let it fail the attempt). The lock
	// is released before the session is closed, since the session's end
	// takes it.
	lock := d.sessions().attemptLock(attemptID)
	lock.Lock()
	err = repo.SetState(ctx, attemptID, []State{StatePreparing, StateProposed, StateApproved}, StateRefused, cause)
	lock.Unlock()
	if err != nil {
		return err
	}
	d.sessions().Close(attemptID)
	d.cleanup(ctx, a, true)
	return d.record(ctx, "fix.refuse", attemptID, "ok", map[string]any{
		"attempt_id": attemptID, "finding_id": a.FindingID, "project_id": a.ProjectID, "has_reason": reason != "", "author": d.actor(),
	})
}
