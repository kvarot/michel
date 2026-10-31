package fix

import (
	"context"
	"errors"
	"path"

	"github.com/kvarot/michel/internal/decide"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/servercheck"
	"github.com/kvarot/michel/internal/serverfix"
	"github.com/kvarot/michel/internal/serverrules"
	"github.com/kvarot/michel/internal/target"
)

// The autonomy levels of a server (spec § 9): at level 2 Michel prepares a
// fix for each open finding by itself and the fix waits for the user; at
// level 3 it also runs, without a click, the fixes that keep every rule of
// AutoApplicableServer.

// EligibleServer reports whether Michel prepares a fix of server finding f
// by itself (fix level 2 or more): an open finding of a server (new,
// pending, or decided "fix"), never deferred nor ignored, on an active
// server at level 2 or more. decided gives the action of the decision in
// force ("" when none). Attempts already made are checked by the queue.
func EligibleServer(f scan.Finding, t target.Target, decided func(id string) string) bool {
	if !t.Active || t.FixLevel < 2 || f.ProjectID != t.ID {
		return false
	}
	if f.Kind != scan.KindServerConfig && f.Kind != scan.KindServerPackage {
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

// AutoApplicableServer tells whether a validated server fix runs without a
// click (spec § 9), checked by Michel, never by the agent. Every rule is
// required: the server is active, at level 3, its rule « corriger seul les
// réglages à risque connus » is checked (AutoConfig) and Michel runs its
// fixes (executor michel); the fix is Michel's own (origin michel.server or
// manual, never an agent's); it only sets directives of Michel's embedded
// rules to their advised value (no package upgrade, no snapshot needed),
// with a configuration test and a site check (the server has a site_url);
// a fix of files owned by root needs sudo without a password; and when the
// server has a preprod, the same fix was proven there first
// (preprodProven, which the caller looks up).
func AutoApplicableServer(t target.Target, p serverfix.Plan, origin string, preprodProven bool) bool {
	if !t.Active || t.FixLevel != 3 || !t.AutoConfig || t.Executor != target.ExecMichel || t.SiteURL == "" {
		return false
	}
	if origin != OriginServer && origin != OriginManual {
		return false
	}
	if t.PreprodID != "" && !preprodProven {
		return false
	}
	if p.NeedsSnapshot || len(p.Actions) == 0 {
		return false
	}
	set, err := serverrules.Rules()
	if err != nil {
		return false
	}
	advised := map[string]string{}
	for _, r := range set.Config {
		if r.Advised != "" {
			advised[r.Directive] = r.Advised
		}
	}
	writes, tests, sites, root := 0, 0, 0, false
	for _, a := range p.Actions {
		switch a.Op {
		case serverfix.OpBackup, serverfix.OpReload:
		case serverfix.OpTestConfig:
			tests++
		case serverfix.OpCheckSite:
			sites++
		case serverfix.OpSetDirective:
			want, ok := advised[a.Directive]
			if !ok || a.Value != want {
				return false
			}
			writes++
			if path.Base(a.Path) != ".user.ini" {
				root = true
			}
		default:
			// package_upgrade and anything else.
			return false
		}
	}
	if writes == 0 || tests == 0 || sites == 0 {
		return false
	}
	if root && t.Sudo != target.SudoNopasswd {
		return false
	}
	return true
}

// QueueEligibleServer puts the eligible findings of server targetID in the
// queue of automatic attempts and returns how many it queued. A server
// below level 2 queues nothing. A finding Michel already tried (any attempt,
// on the server or on its preprod) is not queued again: Michel tries once
// alone, the user starts the next try.
func QueueEligibleServer(ctx context.Context, d Deps, targetID string) (int, error) {
	if d.Targets == nil {
		return 0, errors.New("the fix service needs the server registry")
	}
	t, err := d.Targets.Get(ctx, targetID)
	if err != nil {
		return 0, err
	}
	if t.FixLevel < 2 || !t.Active {
		return 0, nil
	}
	findings, err := scan.NewRepo(d.Store).ListServerFindings(ctx, t.ID)
	if err != nil {
		return 0, err
	}
	current, err := decide.NewRepo(d.Store).CurrentByProject(ctx, t.ID)
	if err != nil {
		return 0, err
	}
	decided := func(id string) string {
		if dec, ok := current[id]; ok {
			return string(dec.Action)
		}
		return ""
	}
	// A finding Michel has no ready-made fix for is queued only when an
	// agent may help (the server's consent, never a health server).
	agentOK, err := d.serverConsentOK(ctx, t)
	if err != nil {
		return 0, err
	}
	inv, hasInv, err := d.Targets.LatestInventory(ctx, t.ID)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, f := range findings {
		if !EligibleServer(f, t, decided) {
			continue
		}
		if tried, err := d.serverTried(ctx, t, f); err != nil {
			return n, err
		} else if tried {
			continue
		}
		if !agentOK {
			if !hasInv {
				continue
			}
			if _, err := planFor(f, t, inv); errors.Is(err, ErrNeedsAgent) {
				continue
			}
		}
		if err := d.repo().Enqueue(ctx, f.ID, t.ID); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// serverTried reports whether finding f of t has an attempt: its own, or
// one on t's preprod made for it.
func (d Deps) serverTried(ctx context.Context, t target.Target, f scan.Finding) (bool, error) {
	attempts, err := d.repo().AttemptsOf(ctx, f.ID)
	if err != nil {
		return false, err
	}
	if len(attempts) > 0 {
		return true, nil
	}
	if t.PreprodID == "" {
		return false, nil
	}
	pre, err := d.repo().ListAttempts(ctx, t.PreprodID, "")
	if err != nil {
		return false, err
	}
	for _, a := range pre {
		if a.Work.Server != nil && a.Work.Server.ProdFindingID == f.ID {
			return true, nil
		}
	}
	return false, nil
}

// workServer is WorkOnce for a queued finding of a server: Michel's own fix
// when it has one, else (and only with the server's AI consent, never for a
// health server) an agent started alone. It reports whether an attempt was
// started; requeue is true when the server was busy.
func (d Deps) workServer(ctx context.Context, f scan.Finding, t target.Target) (started, requeue bool, err error) {
	dec, has, err := decide.NewRepo(d.Store).Current(ctx, f.ID)
	if err != nil {
		return false, false, err
	}
	decided := func(string) string {
		if has {
			return string(dec.Action)
		}
		return ""
	}
	if !EligibleServer(f, t, decided) {
		return false, false, nil
	}
	if tried, err := d.serverTried(ctx, t, f); err != nil || tried {
		return false, false, err
	}
	auto := d
	auto.Actor = "serve"
	_, err = StartServer(ctx, auto, f.ID)
	if errors.Is(err, ErrNeedsAgent) {
		switch ok, cerr := d.serverConsentOK(ctx, t); {
		case cerr != nil:
			return false, false, cerr
		case healthTarget(t):
			err = ErrHealthForbidden
		case !ok:
			err = ErrConsentRequired
		default:
			_, err = auto.startServerAgent(ctx, f.ID, OriginAgentAuto)
		}
	}
	switch {
	case err == nil:
		return true, false, nil
	case errors.Is(err, ErrBusy):
		return false, true, nil
	}
	if key := ErrorKey(err); key != "" {
		_ = d.record(ctx, "fix.start", f.ID, "refused", map[string]any{"finding_id": f.ID, "target_id": t.ID, "origin": "serve", "reason": key})
		return false, false, nil
	}
	return false, false, err
}

// ApplyAutoServer runs, without a click, the server fixes waiting for the
// user that keep every level 3 rule (AutoApplicableServer), one after the
// other, and returns how many it ran. The fix is validated again against
// the server's latest inventory first. A server with a fix whose state is
// unknown or running gets none. A fix that ran tells the user
// (Alert applied_auto); a fix that failed was already told by its run.
// The worker of michel serve calls it at each pass.
func ApplyAutoServer(ctx context.Context, d Deps) (int, error) {
	if d.Targets == nil {
		return 0, nil
	}
	waiting, err := d.repo().ListAttempts(ctx, "", string(StateProposed))
	if err != nil {
		return 0, err
	}
	n := 0
	for _, a := range waiting {
		if a.Work.Server == nil || (a.Origin != OriginServer && a.Origin != OriginManual) {
			continue
		}
		ran, err := d.autoServer(ctx, a)
		if err != nil {
			_ = d.record(ctx, "server_fix.auto", a.ID, "error", map[string]any{"attempt_id": a.ID, "target_id": a.ProjectID, "error": serverErrorKey(err), "detail": auditDetail(d, err)})
		}
		if ran {
			n++
		}
	}
	return n, nil
}

// autoServer applies one waiting server fix alone when the level 3 rules
// allow it; ran tells whether its script was sent.
func (d Deps) autoServer(ctx context.Context, a Attempt) (ran bool, err error) {
	t, err := d.Targets.Get(ctx, a.ProjectID)
	if err != nil {
		return false, err
	}
	if t.FixLevel != 3 || !t.AutoConfig {
		return false, nil
	}
	prop, ok, err := d.repo().CurrentProposal(ctx, a.ID)
	if err != nil || !ok || prop.Server == nil || prop.Scripts == nil {
		return false, err
	}
	// No fix runs alone next to one whose outcome is not known.
	for _, st := range []State{StateUnknown, StateRunning} {
		list, err := d.repo().ListAttempts(ctx, t.ID, string(st))
		if err != nil {
			return false, err
		}
		if len(list) > 0 {
			return false, nil
		}
	}
	inv, ok, err := d.Targets.LatestInventory(ctx, t.ID)
	if err != nil || !ok {
		return false, err
	}
	sf := *prop.Server
	v, err := serverfix.Validate(serverfix.Plan{TargetID: sf.TargetID, FindingID: sf.FindingID, Mitigation: sf.Mitigation, Actions: sf.Actions}, t, inv)
	if err != nil {
		// Validate refuses an untestable binary, among others.
		return false, nil
	}
	proven, err := d.preprodProven(ctx, t, sf.FindingID)
	if err != nil {
		return false, err
	}
	if !AutoApplicableServer(t, v, a.Origin, proven) || sf.Executor != target.ExecMichel ||
		(prop.Scripts.RunAsRoot && t.Sudo != target.SudoNopasswd) || executorFor(t, *prop.Scripts) != target.ExecMichel {
		return false, nil
	}
	auto := d
	auto.Actor = ActorAuto
	if err := Approve(ctx, auto, a.ID, prop.Hash); err != nil {
		return false, err
	}
	_ = auto.record(ctx, "server_fix.auto", a.ID, "ok", map[string]any{"attempt_id": a.ID, "target_id": t.ID, "finding_id": sf.FindingID, "hash": prop.Hash})
	aerr := Apply(ctx, auto, a.ID)
	got, gerr := d.repo().GetAttempt(ctx, a.ID)
	if gerr != nil {
		return true, errors.Join(aerr, gerr)
	}
	switch got.State {
	case StateApplied, StateProvenFixed, StateInconclusive:
		d.alert(ctx, servercheck.AlertInput{Target: t, Kind: servercheck.AlertAppliedAuto})
	}
	return got.State != StateApproved, aerr
}

// preprodProven tells whether the preprod of t proved the fix of the
// production finding findingID (a proven_fixed preprod attempt made for it).
func (d Deps) preprodProven(ctx context.Context, t target.Target, findingID string) (bool, error) {
	if t.PreprodID == "" {
		return false, nil
	}
	list, err := d.repo().ListAttempts(ctx, t.PreprodID, string(StateProvenFixed))
	if err != nil {
		return false, err
	}
	for _, a := range list {
		if a.Work.Server != nil && a.Work.Server.ProdTargetID == t.ID && a.Work.Server.ProdFindingID == findingID {
			return true, nil
		}
	}
	return false, nil
}
