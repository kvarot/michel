package target

import (
	"context"
	"errors"
	"strings"

	"github.com/kvarot/michel/internal/audit"
	"github.com/kvarot/michel/internal/policy"
)

// Patch is what is asked to change on a server: a nil field is left as it
// is. The text fields are trimmed; CheckInterval is parsed like at the add,
// Preprod is a server's id or name ("" for none).
type Patch struct {
	Alias, Host, User, SiteURL *string
	Port                       *int
	Kind                       *Kind
	Env                        *Env
	Classification             *policy.Classification
	FixLevel                   *int
	Executor                   *Executor
	Sudo                       *SudoMode
	AutoConfig, Active         *bool
	CheckInterval, Preprod     *string
}

// ApplyUpdate changes the server old as p asks, the one way the page and
// michel target set share. The checks come in one order: the interval, the
// fields (Check), the role (CheckEnv), the preprod. When the host or the
// site changes, the new network rules go in first, so a refusal of the
// policy file changes nothing (RulesError), and they come out again when
// the update cannot be stored; once it is stored, the rules of the old host
// and site that no other server uses go. The audit event target.update
// closes it, its list changed naming the fields as the page does; an
// AuditError comes with the server as updated.
func ApplyUpdate(ctx context.Context, d Deps, old Target, p Patch) (Target, error) {
	t := old
	var changed []string
	str := func(v *string, name string, dst *string) {
		if v != nil {
			*dst = strings.TrimSpace(*v)
			changed = append(changed, name)
		}
	}
	str(p.Alias, "alias", &t.Alias)
	str(p.Host, "host", &t.Host)
	str(p.User, "user", &t.User)
	str(p.SiteURL, "site_url", &t.SiteURL)
	set := func(ok bool, name string, do func()) {
		if ok {
			do()
			changed = append(changed, name)
		}
	}
	set(p.Port != nil, "port", func() { t.Port = *p.Port })
	set(p.Kind != nil, "kind", func() { t.Kind = *p.Kind })
	set(p.Env != nil, "env", func() { t.Env = *p.Env })
	set(p.Classification != nil, "classification", func() { t.Classification = *p.Classification })
	set(p.FixLevel != nil, "fix_level", func() { t.FixLevel = *p.FixLevel })
	set(p.Executor != nil, "executor", func() { t.Executor = *p.Executor })
	set(p.Sudo != nil, "sudo", func() { t.Sudo = *p.Sudo })
	set(p.AutoConfig != nil, "auto_config", func() { t.AutoConfig = *p.AutoConfig })
	set(p.Active != nil, "active", func() { t.Active = *p.Active })
	var err error
	if p.CheckInterval != nil {
		if t.CheckInterval, err = ParseInterval(*p.CheckInterval); err != nil {
			return Target{}, err
		}
		changed = append(changed, "check_interval")
	}
	if err := Check(t); err != nil {
		return Target{}, err
	}
	if err := d.Repo.CheckEnv(ctx, t); err != nil {
		return Target{}, err
	}
	if p.Preprod != nil {
		if t.PreprodID, err = d.Repo.ResolvePreprod(ctx, t, *p.Preprod); err != nil {
			return Target{}, err
		}
		changed = append(changed, "preprod")
	}
	// A server that moved is not the one whose fingerprint was confirmed:
	// Update clears the pin with the address.
	moved := t.Host != old.Host || portOf(t.Port) != portOf(old.Port)
	rewrite := t.Host != old.Host || t.SiteURL != old.SiteURL
	var fresh []policy.AllowRule
	if rewrite {
		if fresh, _, err = ChangeRules(ctx, d, AllowRules(t), nil); err != nil {
			return Target{}, &RulesError{Err: err}
		}
	}
	if err := d.Repo.Update(ctx, t); err != nil {
		if len(fresh) > 0 {
			_, _, _ = ChangeRules(ctx, d, nil, fresh)
		}
		return Target{}, err
	}
	// Once the update is stored, the work ends even if the caller goes away:
	// the old rules released half-way, or a change without its trace, would
	// be left behind.
	ctx = context.WithoutCancel(ctx)
	released := 0
	if rewrite {
		if others, err := otherTargets(ctx, d.Repo, t.ID); err == nil {
			gone := ReleasedRules(old, append(others, t))
			if _, done, err := ChangeRules(ctx, d, nil, gone); err == nil {
				released = len(done)
			}
		}
	}
	if _, err := d.Audit.Record(ctx, audit.Event{Actor: d.Actor, Action: "target.update", Target: t.ID, Result: "ok",
		Evidence: map[string]any{"name": t.Name, "changed": changed, "rules_written": len(fresh), "rules_removed": released,
			"host_key_reset": moved && old.HostKey != ""}}); err != nil {
		return t, &AuditError{Err: err}
	}
	return t, nil
}

func portOf(p int) int {
	if p == 0 {
		return 22
	}
	return p
}

// otherTargets are the servers other than id.
func otherTargets(ctx context.Context, repo *Repo, id string) ([]Target, error) {
	all, err := repo.List(ctx)
	if err != nil {
		return nil, err
	}
	out := all[:0:0]
	for _, t := range all {
		if t.ID != id {
			out = append(out, t)
		}
	}
	return out, nil
}

// ErrLogsNotErased is a server that stays because what Michel read in its
// logs could not be erased: removing it can be tried again.
var ErrLogsNotErased = errors.New("what Michel read in the server's logs could not be erased")

// RemoveResult is how the network rules of a removed server went.
type RemoveResult struct {
	// RulesRemoved counts the rules taken back; RulesFailed is a rule edit
	// that failed: the server is gone, its rules stay in the policy file.
	RulesRemoved int
	RulesFailed  bool
}

// Remove takes the server t out of Michel, the one way the page and michel
// target remove share; nothing is done on the server. The caller holds the
// locks of the server (no check, no read of its logs) and has made sure no
// fix is on it. eraseLogs erases what Michel read in its logs, first: when
// it says nothing was erased the server stays (ErrLogsNotErased), since once
// it is gone nothing could erase them; its error is a partial erasure,
// recorded in the trace. Then the server goes, the network rules no other
// server uses are taken back, and the audit event target.remove closes it.
// From the erasure on, the caller going away stops nothing.
func Remove(ctx context.Context, d Deps, t Target, eraseLogs func(context.Context) (erased bool, err error)) (RemoveResult, error) {
	others, err := otherTargets(ctx, d.Repo, t.ID)
	if err != nil {
		return RemoveResult{}, err
	}
	dependents := 0
	for _, o := range others {
		if o.PreprodID == t.ID {
			dependents++
		}
	}
	ctx = context.WithoutCancel(ctx)
	erased, forgetErr := eraseLogs(ctx)
	if !erased {
		return RemoveResult{}, ErrLogsNotErased
	}
	if err := d.Repo.Remove(ctx, t.ID); err != nil {
		return RemoveResult{}, err
	}
	// The opt-in goes with the server, except for what another still uses.
	var res RemoveResult
	if gone := ReleasedRules(t, others); len(gone) > 0 {
		_, done, err := ChangeRules(ctx, d, nil, gone)
		res.RulesRemoved, res.RulesFailed = len(done), err != nil
	}
	if _, err := d.Audit.Record(ctx, audit.Event{Actor: d.Actor, Action: "target.remove", Target: t.ID, Result: "ok",
		Evidence: map[string]any{"name": t.Name, "rules_removed": res.RulesRemoved, "rules_error": res.RulesFailed,
			"preprod_cleared": dependents, "logs_error": forgetErr != nil}}); err != nil {
		return res, &AuditError{Err: err}
	}
	return res, nil
}

// The refusals of a host key confirmation.
var (
	ErrFingerprintMismatch    = errors.New("the fingerprint typed is not the one the server shows")
	ErrHostKeyReplaceNotAsked = errors.New("the server shows another key than the one confirmed, and replacing it was not asked")
)

// RefusalAuditError is a refusal whose audit event could not be written:
// both are told (errors.Is finds the refusal).
type RefusalAuditError struct{ Refusal, Err error }

func (e *RefusalAuditError) Error() string {
	return e.Refusal.Error() + "; the audit log could not be written: " + e.Err.Error()
}
func (e *RefusalAuditError) Unwrap() []error { return []error{e.Refusal, e.Err} }

// ConfirmHostKey pins shown, the fingerprint the server shows now (the
// caller reads it), as t's host key, but only when it is the one the user
// typed, and, when another key was confirmed before, only if replace is
// asked. A refusal is audited refused; the pin is audited with whether it
// replaced another key, which it returns.
func ConfirmHostKey(ctx context.Context, d Deps, t Target, typed, shown string, replace bool) (replaced bool, err error) {
	refuse := func(reason string, refusal error) error {
		if _, err := d.Audit.Record(ctx, audit.Event{Actor: d.Actor, Action: "target.hostkey", Target: t.ID, Result: "refused",
			Evidence: map[string]any{"name": t.Name, "reason": reason}}); err != nil {
			return &RefusalAuditError{Refusal: refusal, Err: err}
		}
		return refusal
	}
	if strings.TrimSpace(typed) != shown {
		return false, refuse("fingerprint mismatch", ErrFingerprintMismatch)
	}
	replaced = t.HostKey != "" && t.HostKey != shown
	if replaced && !replace {
		return false, refuse("key changed, replace not asked", ErrHostKeyReplaceNotAsked)
	}
	if err := d.Repo.SetHostKey(ctx, t.ID, shown); err != nil {
		return false, err
	}
	// The key is pinned: its trace is written even if the caller goes away.
	ctx = context.WithoutCancel(ctx)
	if _, err := d.Audit.Record(ctx, audit.Event{Actor: d.Actor, Action: "target.hostkey", Target: t.ID, Result: "ok",
		Evidence: map[string]any{"name": t.Name, "fingerprint": shown, "replaced": replaced}}); err != nil {
		return replaced, &AuditError{Err: err}
	}
	return replaced, nil
}
