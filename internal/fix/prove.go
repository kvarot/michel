package fix

import (
	"context"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/workcopy"
)

// Pass tells which tools looked at a project in one pass of michel scan. Only
// a tool that looked can settle a fix of what it reports.
type Pass struct {
	// Scanned: the OSV scan read the lockfiles of the project. A scan that
	// found none leaves the findings as they were and proves nothing.
	Scanned bool
	// Sources are the plugin sources that ran and stored their results in
	// this pass. A plugin turned off, not meant to run, or failed is not one.
	Sources map[string]bool
}

// looked tells whether the source of a finding looked in this pass ("" is the
// OSV scan).
func (p Pass) looked(sourceKey string) bool {
	if sourceKey == "" {
		return p.Scanned
	}
	return p.Sources[sourceKey]
}

// Prove settles the applied attempts of the project at the end of a pass,
// once every tool of the pass has run: an attempt is proven_fixed when the
// tool that reported the finding no longer sees it and the fix commit is in
// the current branch of the user's repository (workcopy.IsMerged); gone
// without the merge, or merged but still seen, it is inconclusive (the
// finding keeps the status the tool gave it). When that tool did not look in
// this pass (see Pass), the attempt stays applied, whatever the status says:
// the status is older than this pass. It returns the number proven.
func Prove(ctx context.Context, d Deps, projectID string, pass Pass) (int, error) {
	repo := d.repo()
	lang := d.lang()
	applied, err := repo.ListAttempts(ctx, projectID, string(StateApplied))
	if err != nil {
		return 0, err
	}
	if len(applied) == 0 {
		return 0, nil
	}
	p, err := project.NewRepo(d.Store).Get(ctx, projectID)
	if err != nil {
		return 0, err
	}
	findings, err := scan.NewRepo(d.Store).ListFindings(ctx, projectID, "all")
	if err != nil {
		return 0, err
	}
	status, sourceOf := map[string]string{}, map[string]string{}
	for _, f := range findings {
		status[f.ID], sourceOf[f.ID] = f.Status, f.SourceKey
	}
	proven := 0
	for _, a := range applied {
		if !pass.looked(sourceOf[a.FindingID]) {
			continue
		}
		prop, ok, err := repo.CurrentProposal(ctx, a.ID)
		if err != nil {
			return proven, err
		}
		if !ok {
			continue
		}
		merged := false
		if workcopy.IsGitRepo(p.Path) {
			if merged, err = workcopy.IsMerged(ctx, d.work(), p, prop.CommitSHA); err != nil {
				return proven, err
			}
		}
		gone := status[a.FindingID] == scan.StatusGone
		switch {
		case gone && merged:
			if err := repo.SetState(ctx, a.ID, []State{StateApplied}, StateProvenFixed, ""); err != nil {
				return proven, err
			}
			proven++
			d.cleanup(ctx, a, false)
			if err := d.record(ctx, "fix.proven", a.ID, "ok", map[string]any{
				"attempt_id": a.ID, "finding_id": a.FindingID, "project_id": a.ProjectID, "hash": prop.Hash, "commit": prop.CommitSHA,
			}); err != nil {
				return proven, err
			}
		case gone && !merged:
			_ = repo.SetState(ctx, a.ID, []State{StateApplied}, StateInconclusive, i18n.T(lang, "fix.cause.gone_not_merged"))
			d.cleanup(ctx, a, false)
		case !gone && merged:
			_ = repo.SetState(ctx, a.ID, []State{StateApplied}, StateInconclusive, i18n.T(lang, "fix.cause.merged_still_seen"))
		}
	}
	return proven, nil
}
