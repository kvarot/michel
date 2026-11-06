package project

import (
	"context"
	"errors"
	"fmt"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/policy"
)

// Patch is a change of a project's settings: only the fields set change.
type Patch struct {
	Classification *policy.Classification
	FixLevel       *int
	AutoFixMinor   *bool
	AutoScan       *bool
	TestCmd        *string
	InstallCmd     *string
	CorePackages   *[]string
	Exclude        *[]string
	Tech           *[]string
	// RiskOverrides are added to the overrides the project already has.
	RiskOverrides map[string]int
}

// fields names the settings the patch changes, in the order the audit keeps.
func (p Patch) fields() []string {
	out := []string{}
	for _, f := range []struct {
		name string
		set  bool
	}{
		{"core_packages", p.CorePackages != nil}, {"exclude", p.Exclude != nil}, {"tech", p.Tech != nil},
		{"risk_overrides", len(p.RiskOverrides) > 0}, {"fix_level", p.FixLevel != nil},
		{"auto_fix_minor", p.AutoFixMinor != nil}, {"auto_scan", p.AutoScan != nil},
		{"classification", p.Classification != nil}, {"test_cmd", p.TestCmd != nil}, {"install_cmd", p.InstallCmd != nil},
	} {
		if f.set {
			out = append(out, f.name)
		}
	}
	return out
}

// UpdateRequest is what is asked to change in a project.
type UpdateRequest struct {
	// Actor is who asks, as the audit names it.
	Actor string
	// Name is the name (or id) of the project.
	Name  string
	Patch Patch
	// Risk, when set, is the policy's risk scoring: the overrides of the
	// project on top of it must stay consistent.
	Risk *policy.RiskConfig
	// AllowInactive lets a removed project be changed, as michel project set
	// does; the page only changes active projects.
	AllowInactive bool
}

// ThresholdError is the refusal of risk overrides whose thresholds contradict
// each other.
type ThresholdError struct {
	AutoFixBelow, HandoffUpTo int
	Err                       error
}

func (e *ThresholdError) Error() string {
	return fmt.Sprintf("risk overrides give auto_fix_below=%d and handoff_up_to=%d: %v", e.AutoFixBelow, e.HandoffUpTo, e.Err)
}

func (e *ThresholdError) Unwrap() error { return e.Err }

// Update changes the settings of a project, the one way the page and
// michel project set share, and audits it as project.update: ok with the
// settings changed, denied with the key of the reason, not_found for an
// unknown (or removed) project, error for a storage failure. Refusals are
// *RefusalError, an unknown project ErrNotFound, and an audit that cannot be
// written an *AuditError (the project is changed then when it is ok).
func Update(ctx context.Context, repo *Repo, log *audit.Logger, req UpdateRequest) (Project, error) {
	ev := map[string]any{"fields": req.Patch.fields()}
	record := func(result, reason string, failure error) (Project, error) {
		if reason != "" {
			ev["reason"] = reason
		}
		if _, err := log.Record(ctx, audit.Event{Actor: req.Actor, Action: "project.update",
			Target: boundedForAudit(req.Name, maxProjectName), Result: result, Evidence: ev}); err != nil {
			return Project{}, &AuditError{Err: err, After: failure}
		}
		return Project{}, failure
	}
	refuse := func(key string, cause error) (Project, error) {
		return record("denied", key, &RefusalError{Key: key, Err: cause})
	}
	pt := req.Patch
	if len(ev["fields"].([]string)) == 0 {
		return refuse("api.project.patch.nothing", nil)
	}
	get := repo.GetActive
	if req.AllowInactive {
		get = repo.Get
	}
	p, err := get(ctx, req.Name)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return record("not_found", "project not found", err)
		}
		return record("error", boundedForAudit(err.Error(), maxPathLen), err)
	}
	if pt.CorePackages != nil {
		p.CorePackages = *pt.CorePackages
	}
	if pt.Exclude != nil {
		p.Exclude = *pt.Exclude
		ev["exclude"] = p.Exclude
	}
	if pt.Tech != nil {
		p.Tech = *pt.Tech
		ev["tech"] = p.Tech
	}
	if p.RiskOverrides == nil {
		p.RiskOverrides = map[string]int{}
	}
	for k, v := range pt.RiskOverrides {
		p.RiskOverrides[k] = v
	}
	if pt.FixLevel != nil {
		p.FixLevel, ev["fix_level"] = *pt.FixLevel, *pt.FixLevel
	}
	if pt.AutoFixMinor != nil {
		p.AutoFixMinor, ev["auto_fix_minor"] = *pt.AutoFixMinor, *pt.AutoFixMinor
	}
	if pt.AutoScan != nil {
		p.AutoScan, ev["auto_scan"] = *pt.AutoScan, *pt.AutoScan
	}
	if pt.Classification != nil {
		p.Classification = *pt.Classification
	}
	if pt.TestCmd != nil {
		p.TestCmd = *pt.TestCmd
	}
	if pt.InstallCmd != nil {
		p.InstallCmd = *pt.InstallCmd
	}
	if req.Risk != nil {
		merged := req.Risk.WithOverrides(p.RiskOverrides)
		if verr := policy.ValidateRisk(merged); verr != nil {
			return refuse("cli.project.set.bad_thresholds", &ThresholdError{
				AutoFixBelow: merged.AutoFixBelow, HandoffUpTo: merged.HandoffUpTo, Err: verr})
		}
	}
	if err := repo.Update(ctx, p); err != nil {
		if key := updateRefusalKey(err); key != "" {
			return refuse(key, err)
		}
		return record("error", boundedForAudit(err.Error(), maxPathLen), err)
	}
	if _, err := log.Record(ctx, audit.Event{Actor: req.Actor, Action: "project.update", Target: p.Name, Result: "ok", Evidence: ev}); err != nil {
		return p, &AuditError{Err: err}
	}
	return p, nil
}

// updateRefusalKey is the catalog key of a validation error of Repo.Update,
// "" for any other error.
func updateRefusalKey(err error) string {
	if errors.Is(err, ErrInvalidFixLevel) {
		return "api.project.patch.bad_level"
	}
	if errors.Is(err, ErrNotFound) {
		return ""
	}
	return addRefusalKey(err)
}

// GetActive finds an active project by id, then by name: a removed project
// is as unknown as one that never existed.
func (r *Repo) GetActive(ctx context.Context, nameOrID string) (Project, error) {
	p, err := r.Get(ctx, nameOrID)
	if err != nil {
		return Project{}, err
	}
	if !p.Active {
		return Project{}, fmt.Errorf("%w: %s", ErrNotFound, nameOrID)
	}
	return p, nil
}
