package fix

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/servercheck"
	"github.com/kvarot/michel/internal/serverfix"
	"github.com/kvarot/michel/internal/sshx"
	"github.com/kvarot/michel/internal/target"
)

// Nothing here logs or audits what a server printed: a script's error
// output is only looked at to tell its own outcome lines apart, a
// simulation's output is parsed, a backup's content is kept encrypted;
// none of them is stored as text, logged or audited. Audit events carry
// ids, hashes, exit statuses, error keys and counts.

// Bounds of a fix script's run. They replace, for the scripts only, the
// collection's per-command cap: an apt-get with triggers easily takes
// minutes, and a running fix is never killed.
const (
	DefaultConfigApplyTimeout  = 5 * time.Minute
	DefaultPackageApplyTimeout = 30 * time.Minute
	// recordTimeout bounds what Michel records after a run, under a
	// context the caller cannot cancel.
	recordTimeout = 2 * time.Minute
	// runningMargin is added to the longest bound before Sweep takes a
	// running attempt of a stopped process for lost.
	runningMargin = 10 * time.Minute
)

func (d Deps) applyBound(pkg bool) time.Duration {
	if pkg {
		if d.PackageApplyTimeout > 0 {
			return d.PackageApplyTimeout
		}
		return DefaultPackageApplyTimeout
	}
	if d.ConfigApplyTimeout > 0 {
		return d.ConfigApplyTimeout
	}
	return DefaultConfigApplyTimeout
}

// Fixed details of the steps (English, Michel's own words).
const (
	detailDone        = "done"
	detailNotRun      = "not run"
	detailStopped     = "stopped before any change"
	detailRolledBack  = "failed after the change; the script put the files back"
	detailRollbackBad = "failed, and putting the files back failed too"
	detailPkgFailed   = "the upgrade failed; the package may have changed"
	detailStderr      = "PHP complained while reading the file"
	detailSiteDown    = "the site does not answer"
	detailNoSiteCheck = "no site check is possible from this computer"
	detailStillSeen   = "the check still sees the problem"
	detailPartial     = "the check could not judge everything"
	detailCheckFailed = "the check did not complete"
	detailProven      = "the check no longer sees the problem"
	detailUnknown     = "the run ended without an answer (time limit or connection lost)"
)

// shArgv is how a bundle is sent: on standard input, to `sudo -n sh -s`
// for a root bundle (Michel only runs one with sudo nopasswd), `sh -s`
// for a .user.ini one.
func shArgv(b serverfix.Bundle) []string {
	if b.RunAsRoot {
		return []string{"sudo", "-n", "sh", "-s"}
	}
	return []string{"sh", "-s"}
}

// serverRun is one Apply of a server fix in progress.
type serverRun struct {
	d    Deps
	a    Attempt
	prop Proposal
	sf   ServerFix
	t    target.Target
	b    serverfix.Bundle // the scripts rendered again, equal to the validated ones
	// bg is the run's context, which the caller cannot cancel: the undo
	// script runs under it with its own bound; what is recorded after the
	// script runs under a context bounded by recordTimeout.
	bg    context.Context
	plan  serverfix.Plan
	steps []StepResult
}

func (r *serverRun) step(op, detail string, ok bool) {
	s := StepResult{Op: op, OK: ok, Detail: detail}
	r.steps = append(r.steps, s)
	if r.d.OnStep != nil {
		r.d.OnStep(r.a.ID, s)
	}
}

// pkg tells whether the fix upgrades a package: no script can undo it.
func (r *serverRun) pkg() bool { return r.plan.NeedsSnapshot || r.sf.NeedsSnapshot }

// keep runs f and logs its error: what Michel records after a run must
// never be dropped silently.
func keep(what string, attemptID string, err error) error {
	if err != nil {
		slog.Warn("server fix: cannot record", "what", what, "attempt", attemptID, "err", err)
	}
	return err
}

// fresh is a context of its own for one step after the script: never
// cancelled by the caller, never cut by the steps before it, bounded by d.
func (r *serverRun) fresh(d time.Duration) (context.Context, context.CancelFunc) {
	base := r.bg
	if base == nil {
		base = context.Background()
	}
	return context.WithTimeout(base, d)
}

// The bounds of the steps after the script.
const (
	DefaultSiteCheckTimeout = 30 * time.Second
	DefaultCheckTimeout     = 5 * time.Minute
)

func (d Deps) siteCheckTimeout() time.Duration {
	if d.SiteCheckTimeout > 0 {
		return d.SiteCheckTimeout
	}
	return DefaultSiteCheckTimeout
}

func (d Deps) checkTimeout() time.Duration {
	if d.CheckTimeout > 0 {
		return d.CheckTimeout
	}
	return DefaultCheckTimeout
}

// check runs one recollection under its own bound.
func (r *serverRun) check() (servercheck.CheckResult, error) {
	ctx, cancel := r.fresh(r.d.checkTimeout())
	defer cancel()
	return r.d.CheckServer(ctx, r.t.ID)
}

// alert sends an alert under a context of its own (after the state moved).
func (r *serverRun) alert(in servercheck.AlertInput) {
	ctx, cancel := r.fresh(r.d.recordTimeout())
	defer cancel()
	r.d.alert(ctx, in)
}

func (r *serverRun) saveSteps(_ context.Context) error {
	ctx, cancel := r.fresh(r.d.recordTimeout())
	defer cancel()
	return keep("steps", r.a.ID, r.d.repo().SetSteps(ctx, r.prop.ID, r.steps))
}

// move changes the attempt's state under a context of its own, so a slow
// step before it never leaves the attempt half way; a failure is logged
// and audited.
func (r *serverRun) move(_ context.Context, from []State, to State, cause string) error {
	ctx, cancel := r.fresh(r.d.recordTimeout())
	defer cancel()
	err := r.d.repo().SetState(ctx, r.a.ID, from, to, cause)
	if err != nil {
		keep("state "+string(to), r.a.ID, err)
		_ = r.audit(ctx, "server_fix.state", "error", map[string]any{"attempt_id": r.a.ID, "target_id": r.t.ID, "to": string(to)})
	}
	return err
}

// audit records an event under a context of its own; a failure is logged.
func (r *serverRun) audit(_ context.Context, action, result string, ev map[string]any) error {
	ctx, cancel := r.fresh(r.d.recordTimeout())
	defer cancel()
	return keep(action, r.a.ID, r.d.record(ctx, action, r.a.ID, result, ev))
}

// checked loads what Apply and AppliedByMe need, and checks that the
// approved proposal is the current one and that its stored scripts and
// record still have the hash the user approved. Nothing is sent when it
// fails; a record that no longer matches ends the attempt (failed), so a
// new fix can be prepared.
func (d Deps) checked(ctx context.Context, a Attempt, action string) (*serverRun, error) {
	repo := d.repo()
	prop, ok, err := repo.CurrentProposal(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNoProposal
	}
	refuse := func(reason string, e error) (*serverRun, error) {
		_ = keep(action, a.ID, d.record(ctx, action, a.ID, "refused", map[string]any{"attempt_id": a.ID, "target_id": a.ProjectID, "reason": reason,
			"approved_hash": a.ApprovedHash, "current_hash": prop.Hash}))
		return nil, e
	}
	if prop.ID != a.ApprovedProposal || prop.Hash != a.ApprovedHash || prop.Hash == "" {
		return refuse("proposal changed after approval", ErrStaleProposal)
	}
	if prop.Scripts == nil || prop.Server == nil {
		return d.endRefused(ctx, a, ErrScriptChanged, refuse, "no scripts")
	}
	sf := *prop.Server
	if serverfix.Hash(*prop.Scripts) != prop.Scripts.Hash || serverHash(prop.Scripts.Hash, sf) != prop.Hash || sf.TargetID != a.ProjectID {
		return d.endRefused(ctx, a, ErrScriptChanged, refuse, "stored scripts do not match their hash")
	}
	if d.Targets == nil {
		return nil, errors.New("the fix service needs the server registry")
	}
	t, err := d.Targets.Get(ctx, sf.TargetID)
	if err != nil {
		return nil, err
	}
	return &serverRun{d: d, a: a, prop: prop, sf: sf, t: t}, nil
}

// endRefused audits a refusal and ends the approved attempt with its cause.
func (d Deps) endRefused(ctx context.Context, a Attempt, e error, refuse func(string, error) (*serverRun, error), reason string) (*serverRun, error) {
	_, _ = refuse(reason, e)
	if err := d.repo().SetState(ctx, a.ID, []State{StateApproved}, StateFailed, d.causeOf(e)); err != nil {
		return nil, errors.Join(e, keep("state failed", a.ID, err))
	}
	return nil, e
}

// rebuild validates the stored actions again against the current
// inventory and renders them with the same correction id: the scripts must
// come out byte for byte the validated ones (same hash), or nothing is
// sent (ErrScriptChanged, the attempt ends).
func (r *serverRun) rebuild(ctx context.Context, action string) error {
	inv, ok, err := r.d.Targets.LatestInventory(ctx, r.t.ID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNoInventory
	}
	reason := ""
	v, err := serverfix.Validate(serverfix.Plan{TargetID: r.sf.TargetID, FindingID: r.sf.FindingID, Mitigation: r.sf.Mitigation, Actions: r.sf.Actions}, r.t, inv)
	var b serverfix.Bundle
	switch {
	case err != nil:
		reason = "validation against the current inventory failed"
	default:
		if b, err = serverfix.Render(v, r.t, r.sf.CorrectionID); err != nil {
			reason = "render failed"
		} else if b.Hash != r.prop.Scripts.Hash {
			reason = "scripts differ from the validated ones"
		}
	}
	if reason != "" {
		_ = r.audit(ctx, action, "refused", map[string]any{"attempt_id": r.a.ID, "target_id": r.t.ID, "reason": reason, "hash": r.prop.Hash})
		return errors.Join(ErrScriptChanged, r.move(ctx, []State{StateApproved}, StateFailed, r.d.causeOf(ErrScriptChanged)))
	}
	r.b, r.plan = b, v
	return nil
}

// Apply of a server fix, executor michel, state approved.
//
// Before anything is sent: the scripts are checked against the approved
// hash and rendered again from the current inventory (same hash); the
// executor and sudo mode are checked again on the re-rendered bundle; a
// package upgrade needs its snapshot acknowledged. Then the attempt is
// claimed (approved → running, one conditional update: a second Apply,
// from any process, gets ErrBusy and a Refuse is refused). From there on
// nothing depends on the caller's context: the script and everything
// recorded after it run to their end. A package upgrade is simulated
// again in the same SSH connection right before; the apply script goes on
// standard input, bounded by its own limit and never killed; then Michel
// checks the site from the workstation and checks the server again.
func (d Deps) applyServer(ctx context.Context, a Attempt) error {
	r, err := d.checked(ctx, a, "server_fix.apply")
	if err != nil {
		return err
	}
	if r.sf.NeedsSnapshot {
		if _, _, ok, err := d.repo().SnapshotAck(ctx, a.ID); err != nil {
			return err
		} else if !ok {
			_ = r.audit(ctx, "server_fix.apply", "refused", map[string]any{"attempt_id": a.ID, "target_id": r.t.ID, "reason": "snapshot required"})
			return ErrSnapshotRequired
		}
	}
	if err := r.rebuild(ctx, "server_fix.apply"); err != nil {
		return err
	}
	// Who runs it is judged on the re-rendered bundle and the server's
	// current settings, never on a stored flag.
	if r.sf.Executor != target.ExecMichel {
		// A fix the user runs: it waits for AppliedByMe.
		_ = r.audit(ctx, "server_fix.apply", "refused", map[string]any{"attempt_id": a.ID, "target_id": r.t.ID, "reason": "run by the user"})
		return ErrNotMichelExecutor
	}
	if executorFor(r.t, r.b) != target.ExecMichel {
		// The server's settings changed since the approval: Michel no
		// longer runs it, the attempt ends so a new fix can be prepared.
		_ = r.audit(ctx, "server_fix.apply", "refused", map[string]any{"attempt_id": a.ID, "target_id": r.t.ID, "reason": "not run by Michel any more"})
		return errors.Join(ErrNotMichelExecutor, r.move(ctx, []State{StateApproved}, StateFailed, d.causeOf(ErrNotMichelExecutor)))
	}
	// The deadline stored with the claim is this run's own bound: a sweeper
	// in another process judges the run by it, never by its own settings.
	claimed, err := d.repo().Claim(ctx, a.ID, d.now().Add(d.applyBound(r.pkg())))
	if err != nil {
		return err
	}
	if !claimed {
		return ErrBusy
	}
	r.bg = context.WithoutCancel(ctx)
	return r.run(r.bg)
}

func (d Deps) recordTimeout() time.Duration {
	if d.RecordTimeout > 0 {
		return d.RecordTimeout
	}
	return recordTimeout
}

// run is the claimed part of Apply (state running), under a context the
// caller cannot cancel.
func (r *serverRun) run(ctx context.Context) error {
	d := r.d
	a := r.a
	c, err := sshx.Dial(ctx, d.SSH, r.t)
	if err != nil {
		// Nothing was sent: the fix waits for another try.
		_ = r.audit(ctx, "server_fix.apply", "error", map[string]any{"attempt_id": a.ID, "target_id": r.t.ID, "error": "connect"})
		return errors.Join(fmt.Errorf("cannot connect to server %s: %w", r.t.Name, err), r.move(ctx, []State{StateRunning}, StateApproved, ""))
	}
	defer c.Close()
	if r.pkg() {
		if err := simulate(ctx, c, r.plan, r.t); err != nil {
			r.step(string(serverfix.OpPackageUpgrade), detailNotRun, false)
			return r.fail(ctx, err, "simulation")
		}
	}
	res, err := c.RunWith(ctx, shArgv(r.b), strings.NewReader(r.b.Apply), sshx.RunOptions{Timeout: d.applyBound(r.pkg()), NoKill: true})
	if err != nil {
		if errors.Is(err, sshx.ErrNotStarted) {
			// No session: nothing ran on the server.
			_ = r.audit(ctx, "server_fix.apply", "error", map[string]any{"attempt_id": a.ID, "target_id": r.t.ID, "error": "not started"})
			return errors.Join(err, r.move(ctx, []State{StateRunning}, StateApproved, ""))
		}
		return r.unknown(ctx, c)
	}
	// From here on each step has its own bound (site check, recollection,
	// undo, recording): a slow one never stops the next, and the attempt
	// always ends in a final state.
	code := res.Exit
	// php -c exits 0 on ini warnings: for the CLI test, anything PHP says on
	// its error output is a failure (the script cannot tell). The output
	// itself is never kept.
	stderrFail := code == 0 && len(res.Stderr) > 0 && cliTest(r.plan)
	r.scriptSteps(code, stderrFail)
	r.fetchBackups(ctx, c)
	if code != 0 {
		e := classifyResult(res, r.pkg())
		// The state first, then the alert.
		ferr := r.fail(ctx, e, "exit "+strconv.Itoa(code))
		switch {
		case errors.Is(e, ErrServerRollbackFailed):
			r.alert(servercheck.AlertInput{Target: r.t, Kind: servercheck.AlertRollbackFailed, Urgent: true, Backups: r.backupList()})
		case errors.Is(e, ErrServerRolledBack):
			r.alert(servercheck.AlertInput{Target: r.t, Kind: servercheck.AlertRolledBack})
		case errors.Is(e, ErrPackageFailed):
			r.alert(servercheck.AlertInput{Target: r.t, Kind: servercheck.AlertRestoreSnapshot, Urgent: true})
		}
		switch {
		case errors.Is(e, ErrServerLineMoved):
			c.Close()
			r.repropose(ctx)
		case errors.Is(e, ErrPackageFailed), errors.Is(e, ErrServerRollbackFailed):
			c.Close()
			r.recollect(ctx)
		}
		return ferr
	}
	if err := r.move(ctx, []State{StateRunning}, StateApplied, ""); err != nil {
		return err
	}
	_ = r.audit(ctx, "server_fix.apply", "ok", map[string]any{"attempt_id": a.ID, "target_id": r.t.ID, "finding_id": r.sf.FindingID,
		"hash": r.prop.Hash, "scripts_hash": r.b.Hash, "correction_id": r.sf.CorrectionID, "exit": 0, "author": d.approver(a)})
	if stderrFail {
		return r.undo(ctx, c, "php complained")
	}
	if ok, _ := r.checkSite(ctx); !ok {
		if r.pkg() {
			// No script can take a package back: the snapshot can.
			c.Close()
			return r.siteDownAfterUpgrade(ctx)
		}
		return r.undo(ctx, c, "site check failed")
	}
	c.Close()
	return r.prove(ctx)
}

// unknown ends a run that got no answer (its bound passed, or the
// connection dropped): Michel cannot tell what the script changed, so it
// guesses no undo. The state is unknown, an urgent alert asks to look at
// the server, and the server is checked again.
func (r *serverRun) unknown(ctx context.Context, c *sshx.Client) error {
	c.Close()
	r.step("apply", detailUnknown, false)
	err := r.move(ctx, []State{StateRunning}, StateUnknown, r.d.causeOf(ErrServerUnknownState))
	r.alert(servercheck.AlertInput{Target: r.t, Kind: servercheck.AlertUnknownState, Urgent: true, Backups: r.backupList()})
	_ = r.audit(ctx, "server_fix.apply", "error", map[string]any{"attempt_id": r.a.ID, "target_id": r.t.ID, "finding_id": r.sf.FindingID,
		"hash": r.prop.Hash, "correction_id": r.sf.CorrectionID, "error": "fix.server.unknown_state"})
	r.recollect(ctx)
	return errors.Join(ErrServerUnknownState, err)
}

// siteDownAfterUpgrade ends a package upgrade that took the site down:
// nothing is undone (no script can), an urgent alert asks to restore the
// snapshot.
func (r *serverRun) siteDownAfterUpgrade(ctx context.Context) error {
	err := r.move(ctx, []State{StateApplied}, StateFailed, CauseSiteDownAfterUpgrade)
	r.alert(servercheck.AlertInput{Target: r.t, Kind: servercheck.AlertRestoreSnapshot, Urgent: true})
	_ = r.audit(ctx, "server_fix.apply", "error", map[string]any{"attempt_id": r.a.ID, "target_id": r.t.ID, "finding_id": r.sf.FindingID,
		"hash": r.prop.Hash, "correction_id": r.sf.CorrectionID, "error": "fix.server.site_down_after_upgrade"})
	r.recollect(ctx)
	return errors.Join(ErrSiteDownAfterUpgrade, err)
}

// approver is the actor an attempt was approved by.
func (d Deps) approver(a Attempt) string {
	if a.ApprovedBy != "" {
		return a.ApprovedBy
	}
	return d.actor()
}

// alert tells the user, waiting at most until ctx ends: a channel that
// hangs (SMS, webhook) never holds the attempt. The state is always set
// before an alert is sent.
func (d Deps) alert(ctx context.Context, in servercheck.AlertInput) {
	if d.Alert == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.Alert(ctx, in)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		slog.Warn("server fix: the alert did not return in time", "kind", in.Kind, "target", in.Target.ID)
	}
}

// cliTest tells whether the plan tests a php.ini with the CLI (php -c).
func cliTest(p serverfix.Plan) bool {
	for _, a := range p.Actions {
		if a.Op == serverfix.OpTestConfig && a.SAPI == serverfix.SAPICLI {
			return true
		}
	}
	return false
}

// scriptRolledBack is the line the apply script prints on its error
// output when its trap put the files back (serverfix's own text): only
// then is a failure "rolled back".
const scriptRolledBack = "echec: fichiers remis"

// classifyResult classifies a run by its exit and its error stream: the
// kept head and, when the stream was cut, its kept tail, where the
// script's last line (its outcome) is.
func classifyResult(res sshx.Result, pkg bool) error {
	stderr := res.Stderr
	if res.StderrCut && len(res.StderrTail) > 0 {
		stderr = append(append(append([]byte(nil), res.Stderr...), '\n'), res.StderrTail...)
	}
	return classifyExit(res.Exit, stderr, pkg)
}

// classifyExit tells what a non-zero exit of the apply script means. The
// scripts' own codes first (3 to 8); then sudo's refusal and a shell that
// could not run (126, 127): nothing ran. For a package upgrade, any other
// failure may have changed the package: only the snapshot takes it back.
// For a configuration fix, a failure is "rolled back" only when the script
// says its trap put the files back; otherwise it stopped before any change.
func classifyExit(code int, stderr []byte, pkg bool) error {
	switch code {
	case 0:
		return nil
	case serverfix.ExitNotRoot:
		return ErrServerWrongUser
	case serverfix.ExitApplied:
		return ErrServerAlreadyApplied
	case serverfix.ExitLineMoved:
		return ErrServerLineMoved
	case serverfix.ExitLink:
		return ErrServerLink
	case serverfix.ExitUnsafe:
		return ErrServerUnsafe
	case 126, 127:
		return ErrServerNotRun
	}
	if code == 1 && (bytes.HasPrefix(stderr, []byte("sudo:")) || bytes.Contains(stderr, []byte("\nsudo:"))) {
		return ErrServerSudoRefused
	}
	switch {
	case pkg:
		return ErrPackageFailed
	case code == serverfix.ExitRollbackFail:
		return ErrServerRollbackFailed
	case bytes.Contains(stderr, []byte(scriptRolledBack)):
		return ErrServerRolledBack
	}
	return ErrServerStopped
}

// scriptSteps turns the exit status of the apply script into its steps.
// The script runs as a whole, so a failure is placed on the first step
// that can give it: the first step for a refusal before any change, the
// write for a line that moved, the first test, reload or upgrade for a
// failure after the change.
func (r *serverRun) scriptSteps(code int, stderrFail bool) {
	failsAt := func(a serverfix.Action) (bool, string) {
		later := a.Op == serverfix.OpTestConfig || a.Op == serverfix.OpReload || a.Op == serverfix.OpPackageUpgrade
		switch {
		case code == serverfix.ExitNotRoot || code == serverfix.ExitApplied || code == serverfix.ExitLink || code == serverfix.ExitUnsafe ||
			code == 126 || code == 127:
			return true, detailStopped
		case code == serverfix.ExitLineMoved:
			return a.Op == serverfix.OpSetDirective, detailStopped
		case code != 0 && r.pkg():
			return a.Op == serverfix.OpPackageUpgrade, detailPkgFailed
		case code == serverfix.ExitRollbackFail:
			return later, detailRollbackBad
		case code != 0:
			return later, detailRolledBack
		case stderrFail:
			return a.Op == serverfix.OpTestConfig && a.SAPI == serverfix.SAPICLI, detailStderr
		}
		return false, ""
	}
	failed := false
	for _, a := range r.plan.Actions {
		if a.Op == serverfix.OpCheckSite {
			continue
		}
		if failed {
			r.step(string(a.Op), detailNotRun, false)
			continue
		}
		if bad, detail := failsAt(a); bad {
			failed = true
			r.step(string(a.Op), detail, false)
			continue
		}
		r.step(string(a.Op), detailDone, true)
	}
}

// checkSite runs the workstation checks of the bundle: the GET of the
// site. ok is false when the site does not answer; with no SiteCheck the
// check cannot be made, which is not a failure of the fix but leaves it
// unproven.
func (r *serverRun) checkSite(ctx context.Context) (ok bool, err error) {
	for _, c := range r.b.Checks {
		if c.Op != serverfix.OpCheckSite || r.t.SiteURL == "" {
			continue
		}
		if r.d.SiteCheck == nil {
			r.step(string(serverfix.OpCheckSite), detailNoSiteCheck, false)
			return true, errNoSiteCheck
		}
		sctx, cancel := r.fresh(r.d.siteCheckTimeout())
		err := r.d.SiteCheck(sctx, r.t.SiteURL)
		cancel()
		if err != nil {
			r.step(string(serverfix.OpCheckSite), detailSiteDown, false)
			return false, err
		}
		r.step(string(serverfix.OpCheckSite), detailDone, true)
	}
	return true, nil
}

var errNoSiteCheck = errors.New("no site check")

// undo runs the undo script of a configuration fix at once (the site broke
// after the change, or PHP complained), checks the site again, and ends the
// attempt failed: rolled back, or with an urgent alert and the backups to
// put back by hand when undo failed. A package fix is never "undone" here.
func (r *serverRun) undo(ctx context.Context, c *sshx.Client, reason string) error {
	d := r.d
	runCtx := r.bg
	if runCtx == nil {
		runCtx = context.WithoutCancel(ctx)
	}
	res, err := c.RunWith(runCtx, shArgv(r.b), strings.NewReader(r.b.Undo), sshx.RunOptions{Timeout: d.applyBound(false), NoKill: true})
	undone := err == nil && res.Exit == 0
	if undone {
		r.step(StepUndo, detailDone, true)
	} else {
		r.step(StepUndo, detailRollbackBad, false)
	}
	c.Close()
	siteBack := true
	if d.SiteCheck != nil && r.t.SiteURL != "" {
		sctx, cancel := r.fresh(d.siteCheckTimeout())
		err := d.SiteCheck(sctx, r.t.SiteURL)
		cancel()
		if err != nil {
			siteBack = false
			r.step(string(serverfix.OpCheckSite), detailSiteDown, false)
		} else {
			r.step(string(serverfix.OpCheckSite), detailDone, true)
		}
	}
	exit := -1
	if err == nil {
		exit = res.Exit
	}
	ev := map[string]any{"attempt_id": r.a.ID, "target_id": r.t.ID, "finding_id": r.sf.FindingID, "hash": r.prop.Hash,
		"correction_id": r.sf.CorrectionID, "exit": exit, "site_back": siteBack, "reason": reason}
	var serr error
	if !undone {
		serr = r.move(ctx, []State{StateApplied}, StateFailed, d.causeOf(ErrServerRollbackFailed))
		_ = r.audit(ctx, "server_fix.rollback", "error", ev)
		r.alert(servercheck.AlertInput{Target: r.t, Kind: servercheck.AlertRollbackFailed, Urgent: true, Backups: r.backupList()})
	} else {
		serr = r.move(ctx, []State{StateApplied}, StateFailed, CauseRolledBack)
		_ = r.audit(ctx, "server_fix.rollback", "ok", ev)
		r.alert(servercheck.AlertInput{Target: r.t, Kind: servercheck.AlertRolledBack, Urgent: !siteBack})
	}
	r.recollect(ctx)
	if !undone {
		return errors.Join(ErrServerRollbackFailed, serr)
	}
	return errors.Join(ErrServerRolledBack, serr)
}

// recollect checks the server again, so the findings show the server as it
// is; its outcome changes nothing of the attempt. The steps are saved.
func (r *serverRun) recollect(ctx context.Context) {
	if r.d.CheckServer != nil {
		_, err := r.check()
		r.step(StepRecollect, map[bool]string{true: detailDone, false: detailCheckFailed}[err == nil], err == nil)
	}
	_ = r.saveSteps(ctx)
}

// fail ends an attempt that stopped before or during the script (state
// running or applied → failed) with the cause of e, and returns e.
func (r *serverRun) fail(ctx context.Context, e error, reason string) error {
	d := r.d
	serr := r.move(ctx, []State{StateRunning, StateApplied}, StateFailed, d.causeOf(e))
	_ = r.saveSteps(ctx)
	_ = r.audit(ctx, "server_fix.apply", "error", map[string]any{"attempt_id": r.a.ID, "target_id": r.t.ID, "finding_id": r.sf.FindingID,
		"hash": r.prop.Hash, "correction_id": r.sf.CorrectionID, "error": serverErrorKey(e), "reason": reason, "backups": len(r.backupList())})
	return errors.Join(e, serr)
}

// repropose checks the server again after a line moved since the
// collection and, when the finding is still open, prepares a new fix (a
// new correction id) that waits for the user's approval.
func (r *serverRun) repropose(ctx context.Context) {
	d := r.d
	if d.CheckServer == nil {
		return
	}
	if _, err := r.check(); err != nil {
		r.step(StepRecollect, detailCheckFailed, false)
		_ = r.saveSteps(ctx)
		return
	}
	r.step(StepRecollect, detailDone, true)
	_ = r.saveSteps(ctx)
	list, err := scan.NewRepo(d.Store).FindByIDPrefix(ctx, r.sf.FindingID)
	if err != nil || len(list) != 1 || list[0].Status == scan.StatusGone {
		return
	}
	w := ServerWork{TargetID: r.t.ID}
	if r.a.Work.Server != nil {
		w = *r.a.Work.Server
	}
	pctx, cancel := r.fresh(d.checkTimeout())
	defer cancel()
	na, err := d.proposeServer(pctx, r.t, list[0], w)
	if err != nil {
		_ = r.audit(ctx, "server_fix.repropose", "error", map[string]any{"previous_attempt_id": r.a.ID, "target_id": r.t.ID, "error": serverErrorKey(err)})
		return
	}
	_ = r.audit(ctx, "server_fix.repropose", "ok", map[string]any{"attempt_id": na.ID, "previous_attempt_id": r.a.ID, "target_id": r.t.ID})
}

// backupPaths are the files a bundle backs up, with where each copy lies
// on the server.
func backupPaths(b serverfix.Bundle, sf ServerFix) (bak, file []string) {
	dir := backupDir(b, sf.CorrectionID)
	n := 0
	for _, a := range sf.Actions {
		if a.Op == serverfix.OpBackup {
			n++
			bak = append(bak, dir+"/"+strconv.Itoa(n))
			file = append(file, a.Path)
		}
	}
	return bak, file
}

// BackupList is "backup -> file" for each file a server fix backs up: what
// the page lists for the user to put back by hand (the alert's Backups).
func BackupList(p Proposal) []string {
	if p.Scripts == nil || p.Server == nil {
		return nil
	}
	bak, file := backupPaths(*p.Scripts, *p.Server)
	out := make([]string, len(bak))
	for i := range bak {
		out[i] = bak[i] + " -> " + file[i]
	}
	return out
}

func (r *serverRun) backupList() []string {
	b := r.b
	if b.Apply == "" && r.prop.Scripts != nil {
		b = *r.prop.Scripts
	}
	return BackupList(Proposal{Scripts: &b, Server: &r.sf})
}

// fetchBackups reads the backups the script made, with the scripts' own
// privilege (sudo -n cat for a root bundle, the SSH user for a .user.ini
// one, from its home), and keeps them encrypted on the workstation. Only
// the fixed paths Michel built are read; a backup that is missing, cut or
// unreadable is skipped. Nothing on the server is ever deleted.
func (r *serverRun) fetchBackups(ctx context.Context, c *sshx.Client) {
	if c == nil {
		return
	}
	d := r.d
	ctx, cancel := r.fresh(d.recordTimeout())
	defer cancel()
	have, err := d.backups(ctx, r.a.ID)
	if err != nil {
		keep("backups", r.a.ID, err)
	}
	seen := map[string]bool{}
	for _, b := range have {
		seen[b.RemotePath] = true
	}
	bak, _ := backupPaths(r.b, r.sf)
	for _, p := range bak {
		if seen[p] {
			continue
		}
		var argv []string
		switch {
		case r.b.RunAsRoot && r.t.Sudo == target.SudoNopasswd:
			argv = []string{"sudo", "-n", "cat", p}
		case r.b.RunAsRoot:
			argv = []string{"cat", p}
		default:
			// ~/.michel/... is read from the SSH user's home, the session's
			// folder: no tilde reaches the server.
			argv = []string{"cat", strings.TrimPrefix(p, "~/")}
		}
		res, err := c.Run(ctx, argv, nil)
		if err != nil || res.Exit != 0 || res.Truncated {
			continue
		}
		sum := sha256.Sum256(res.Stdout)
		b := ServerBackup{AttemptID: r.a.ID, TargetID: r.t.ID, RemotePath: p, SHA256: hex.EncodeToString(sum[:]), Content: res.Stdout}
		if err := d.addBackup(ctx, b); err != nil {
			reason := "cannot store"
			if errors.Is(err, errNoKeyStore) {
				reason = "no key store"
			}
			_ = r.audit(ctx, "server_fix.backup", "refused", map[string]any{"attempt_id": r.a.ID, "target_id": r.t.ID, "reason": reason})
			keep("backup", r.a.ID, err)
		}
	}
}

// prove checks the server again after a fix that ran and a site that
// answers: proven_fixed when the check no longer sees the finding, judged
// it fully and the site was checked (when there is one); else
// inconclusive with the cause. A proven preprod fix builds the
// production's.
func (r *serverRun) prove(ctx context.Context) error {
	d := r.d
	lang := d.lang()
	siteChecked := true
	for _, s := range r.steps {
		if s.Op == string(serverfix.OpCheckSite) && !s.OK {
			siteChecked = false
		}
	}
	end := func(detail string, ok bool, to State, cause string) error {
		r.step(StepRecollect, detail, ok)
		_ = r.saveSteps(ctx)
		return r.move(ctx, []State{StateApplied}, to, cause)
	}
	if d.CheckServer == nil {
		return end(detailCheckFailed, false, StateInconclusive, i18n.T(lang, "fix.server.check_failed"))
	}
	res, err := r.check()
	if err != nil {
		return end(detailCheckFailed, false, StateInconclusive, i18n.T(lang, "fix.server.check_failed"))
	}
	list, err := scan.NewRepo(d.Store).FindByIDPrefix(ctx, r.sf.FindingID)
	if err != nil {
		return errors.Join(err, end(detailCheckFailed, false, StateInconclusive, i18n.T(lang, "fix.server.check_failed")))
	}
	var f scan.Finding
	for _, x := range list {
		if x.ID == r.sf.FindingID {
			f = x
		}
	}
	gone := f.ID != "" && f.Status == scan.StatusGone
	partial := !res.Touched || (f.Kind == scan.KindServerPackage &&
		(!res.ReleaseKnown || res.Unjudged > 0 || res.SkippedAdvisories > 0 || res.SourceToEnable != ""))
	switch {
	case gone && !partial && siteChecked:
		if err := end(detailProven, true, StateProvenFixed, ""); err != nil {
			return err
		}
		_ = r.audit(ctx, "server_fix.proven", "ok", map[string]any{"attempt_id": r.a.ID, "target_id": r.t.ID,
			"finding_id": r.sf.FindingID, "hash": r.prop.Hash, "correction_id": r.sf.CorrectionID, "mitigation": r.sf.Mitigation})
		r.promote(ctx)
		return nil
	case !gone:
		return end(detailStillSeen, false, StateInconclusive, i18n.T(lang, "fix.server.still_seen"))
	case !siteChecked:
		return end(detailProven, true, StateInconclusive, i18n.T(lang, "fix.server.site_unchecked"))
	default:
		return end(detailPartial, false, StateInconclusive, i18n.T(lang, "fix.server.check_partial"))
	}
}

// promote builds the production fix once a preprod fix is proven: from the
// production's own inventory (its paths, versions and services), so a new
// hash, waiting for its own approval. A production set to report only
// gets none.
func (r *serverRun) promote(ctx context.Context) {
	d := r.d
	w := r.a.Work.Server
	if w == nil || w.ProdTargetID == "" {
		return
	}
	ev := map[string]any{"preprod_attempt_id": r.a.ID, "target_id": w.ProdTargetID, "finding_id": w.ProdFindingID}
	pt, err := d.Targets.Get(ctx, w.ProdTargetID)
	if err != nil {
		ev["error"] = "server"
		_ = r.audit(ctx, "server_fix.promote", "error", ev)
		return
	}
	if pt.FixLevel == 0 {
		ev["error"] = serverErrorKey(ErrReportOnly)
		_ = r.audit(ctx, "server_fix.promote", "refused", ev)
		return
	}
	list, err := scan.NewRepo(d.Store).FindByIDPrefix(ctx, w.ProdFindingID)
	if err != nil || len(list) != 1 || list[0].Status == scan.StatusGone {
		ev["error"] = serverErrorKey(ErrFindingGone)
		_ = r.audit(ctx, "server_fix.promote", "refused", ev)
		return
	}
	pctx, cancel := r.fresh(d.checkTimeout())
	defer cancel()
	na, err := d.proposeServer(pctx, pt, list[0], ServerWork{TargetID: pt.ID})
	result := "ok"
	if err != nil {
		result, ev["error"] = "error", serverErrorKey(err)
	} else {
		ev["attempt_id"] = na.ID
	}
	_ = r.audit(ctx, "server_fix.promote", result, ev)
}

// AppliedByMe is the user's word that they ran the apply script of an
// approved fix with executor user. Michel fetches the backups it can read,
// checks the site from the workstation and the server again: proven_fixed
// or inconclusive as for Michel's own run. A site that no longer answers
// gives an urgent alert telling the user to run undo now (Michel never
// runs a script it was not allowed to), or to restore the snapshot after a
// package upgrade; the attempt then fails.
func AppliedByMe(ctx context.Context, d Deps, attemptID string) error {
	lock := d.sessions().attemptLock(attemptID)
	lock.Lock()
	defer lock.Unlock()
	a, err := d.repo().GetAttempt(ctx, attemptID)
	if err != nil {
		return err
	}
	if a.Work.Server == nil {
		return ErrNotServerFinding
	}
	if a.State != StateApproved {
		return fmt.Errorf("%w (the attempt is %s)", ErrBadTransition, a.State)
	}
	r, err := d.checked(ctx, a, "server_fix.apply")
	if err != nil {
		return err
	}
	if r.sf.Executor != target.ExecUser {
		return ErrNotUserExecutor
	}
	r.b, r.plan = *r.prop.Scripts, serverfix.Plan{Actions: r.sf.Actions, NeedsSnapshot: r.sf.NeedsSnapshot, Mitigation: r.sf.Mitigation}
	// One conditional update: a second AppliedByMe gets ErrBadTransition.
	if err := d.repo().SetState(ctx, a.ID, []State{StateApproved}, StateApplied, ""); err != nil {
		return err
	}
	r.bg = context.WithoutCancel(ctx)
	ctx = r.bg
	_ = r.audit(ctx, "server_fix.apply", "ok", map[string]any{"attempt_id": a.ID, "target_id": r.t.ID, "finding_id": r.sf.FindingID,
		"hash": r.prop.Hash, "correction_id": r.sf.CorrectionID, "executor": "user", "author": d.actor()})
	dctx, dcancel := r.fresh(d.recordTimeout())
	defer dcancel()
	if c, err := sshx.Dial(dctx, d.SSH, r.t); err == nil {
		r.fetchBackups(ctx, c)
		c.Close()
	}
	r.step("apply", "run by you", true)
	if ok, _ := r.checkSite(ctx); !ok {
		if r.pkg() {
			return r.siteDownAfterUpgrade(ctx)
		}
		serr := r.move(ctx, []State{StateApplied}, StateFailed, d.causeOf(ErrServerSiteDown))
		r.alert(servercheck.AlertInput{Target: r.t, Kind: servercheck.AlertUndoNow, Urgent: true, Backups: r.backupList()})
		_ = r.saveSteps(ctx)
		_ = r.audit(ctx, "server_fix.apply", "error", map[string]any{"attempt_id": a.ID, "target_id": r.t.ID, "error": "fix.server.site_down_user"})
		return errors.Join(ErrServerSiteDown, serr)
	}
	return r.prove(ctx)
}

// simulateOnce connects to t and simulates the package upgrade of v.
func (d Deps) simulateOnce(ctx context.Context, t target.Target, v serverfix.Plan) error {
	c, err := sshx.Dial(ctx, d.SSH, t)
	if err != nil {
		return fmt.Errorf("cannot connect to server %s: %w", t.Name, err)
	}
	defer c.Close()
	return simulate(ctx, c, v, t)
}

// simulate asks the package manager what the upgrade of v would do,
// changing nothing (apt-get -s, dnf --assumeno, apk --simulate), with the
// apply's own privilege (sudo -n when sudo needs no password: dnf needs
// root even to simulate), and refuses (ErrSimulationRefused) anything but
// exactly that upgrade: a removal, a replacement, an error, another
// version. The output is parsed, never kept.
func simulate(ctx context.Context, c *sshx.Client, v serverfix.Plan, t target.Target) error {
	var a serverfix.Action
	for _, x := range v.Actions {
		if x.Op == serverfix.OpPackageUpgrade {
			a = x
		}
	}
	var argv []string
	switch a.Manager {
	case "apt":
		argv = []string{"apt-get", "-s", "install", "--no-remove", "--only-upgrade", a.Package + "=" + a.Version}
	case "dnf":
		argv = []string{"dnf", "--assumeno", "--setopt=obsoletes=False", "upgrade", a.Package + "-" + a.Version}
	case "apk":
		argv = []string{"apk", "add", "--simulate", "--upgrade", a.Package + ">=" + a.Version}
	default:
		return fmt.Errorf("%w: no package manager", ErrSimulationRefused)
	}
	if t.Sudo == target.SudoNopasswd {
		argv = append([]string{"sudo", "-n"}, argv...)
	}
	res, err := c.Run(ctx, argv, nil)
	if err != nil {
		return fmt.Errorf("%w: the simulation did not run", ErrSimulationRefused)
	}
	if res.Truncated || !(res.Exit == 0 || (a.Manager == "dnf" && res.Exit == 1)) {
		return fmt.Errorf("%w: the simulation failed (exit %d)", ErrSimulationRefused, res.Exit)
	}
	if _, err := serverfix.ParseSimulation(a.Manager, string(res.Stdout), a.Package, a.Version); err != nil {
		return fmt.Errorf("%w: %w", ErrSimulationRefused, err)
	}
	return nil
}
