package fix

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/servercheck"
	"github.com/kvarot/michel/internal/serverfix"
	"github.com/kvarot/michel/internal/sshx"
	"github.com/kvarot/michel/internal/target"
)

// Nothing here logs or audits what a server printed: a script's error
// output, a simulation's output or a backup's content never leave this
// file except as the encrypted backup copy. Audit events carry ids, hashes,
// exit statuses and counts.

// Fixed details of the steps (English, Michel's own words).
const (
	detailDone        = "done"
	detailNotRun      = "not run"
	detailStopped     = "stopped before any change"
	detailRolledBack  = "failed after the change; the script put the files back"
	detailRollbackBad = "failed, and putting the files back failed too"
	detailStderr      = "PHP complained while reading the file"
	detailSiteDown    = "the site does not answer"
	detailNoSiteCheck = "no site check is possible from this computer"
	detailStillSeen   = "the check still sees the problem"
	detailPartial     = "the check could not judge everything"
	detailCheckFailed = "the check did not complete"
	detailProven      = "the check no longer sees the problem"
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
	d     Deps
	a     Attempt
	prop  Proposal
	sf    ServerFix
	t     target.Target
	b     serverfix.Bundle // the scripts rendered again, equal to the validated ones
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

func (r *serverRun) saveSteps(ctx context.Context) {
	_ = r.d.repo().SetSteps(ctx, r.prop.ID, r.steps)
}

// checked loads what Apply and AppliedByMe need, and checks that the
// approved proposal is the current one and that its stored scripts and
// record still have the hash the user approved. Nothing is sent when it
// fails.
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
		_ = d.record(ctx, action, a.ID, "refused", map[string]any{"attempt_id": a.ID, "target_id": a.ProjectID, "reason": reason,
			"approved_hash": a.ApprovedHash, "current_hash": prop.Hash})
		return nil, e
	}
	if prop.ID != a.ApprovedProposal || prop.Hash != a.ApprovedHash || prop.Hash == "" {
		return refuse("proposal changed after approval", ErrStaleProposal)
	}
	if prop.Scripts == nil || prop.Server == nil {
		return refuse("no scripts", ErrScriptChanged)
	}
	sf := *prop.Server
	if serverfix.Hash(*prop.Scripts) != prop.Scripts.Hash || serverHash(prop.Scripts.Hash, sf) != prop.Hash || sf.TargetID != a.ProjectID {
		return refuse("stored scripts do not match their hash", ErrScriptChanged)
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

// rebuild validates the stored actions again against the current
// inventory and renders them with the same correction id: the scripts must
// come out byte for byte the validated ones (same hash), or nothing is
// sent (ErrScriptChanged).
func (r *serverRun) rebuild(ctx context.Context, action string) error {
	inv, ok, err := r.d.Targets.LatestInventory(ctx, r.t.ID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNoInventory
	}
	v, err := serverfix.Validate(serverfix.Plan{TargetID: r.sf.TargetID, FindingID: r.sf.FindingID, Mitigation: r.sf.Mitigation, Actions: r.sf.Actions}, r.t, inv)
	var b serverfix.Bundle
	if err == nil {
		b, err = serverfix.Render(v, r.t, r.sf.CorrectionID)
	}
	if err != nil || b.Hash != r.prop.Scripts.Hash {
		_ = r.d.record(ctx, action, r.a.ID, "refused", map[string]any{"attempt_id": r.a.ID, "target_id": r.t.ID,
			"reason": "scripts differ from the validated ones", "hash": r.prop.Hash})
		return ErrScriptChanged
	}
	r.b, r.plan = b, v
	return nil
}

// Apply of a server fix, executor michel: under the attempt's lock, state
// approved. The scripts are checked against the approved hash and rendered
// again from the current inventory (same hash, or nothing is sent); a
// package upgrade is simulated again in the same SSH connection right
// before; the apply script goes on standard input; then Michel checks the
// site from the workstation and checks the server again. A site that no
// longer answers makes Michel run undo at once and check the site again.
func (d Deps) applyServer(ctx context.Context, a Attempt) error {
	r, err := d.checked(ctx, a, "server_fix.apply")
	if err != nil {
		return err
	}
	if r.sf.Executor != target.ExecMichel || r.t.Executor != target.ExecMichel || (r.prop.Scripts.RunAsRoot && r.t.Sudo != target.SudoNopasswd) {
		_ = d.record(ctx, "server_fix.apply", a.ID, "refused", map[string]any{"attempt_id": a.ID, "target_id": r.t.ID, "reason": "not run by Michel"})
		return ErrNotMichelExecutor
	}
	if r.sf.NeedsSnapshot {
		if _, _, ok, err := d.repo().SnapshotAck(ctx, a.ID); err != nil {
			return err
		} else if !ok {
			return ErrSnapshotRequired
		}
	}
	if err := r.rebuild(ctx, "server_fix.apply"); err != nil {
		return err
	}
	c, err := sshx.Dial(ctx, d.SSH, r.t)
	if err != nil {
		_ = d.record(ctx, "server_fix.apply", a.ID, "error", map[string]any{"attempt_id": a.ID, "target_id": r.t.ID, "error": "connect"})
		return fmt.Errorf("cannot connect to server %s: %w", r.t.Name, err)
	}
	defer c.Close()
	if r.plan.NeedsSnapshot {
		if err := simulate(ctx, c, r.plan); err != nil {
			r.step(string(serverfix.OpPackageUpgrade), detailNotRun, false)
			return r.fail(ctx, err, "simulation")
		}
	}
	res, err := c.Run(ctx, shArgv(r.b), strings.NewReader(r.b.Apply))
	if err != nil {
		// The script may have stopped anywhere; its trap puts the files back
		// on a hang-up, but Michel cannot tell: the user must look.
		r.step("apply", "connection lost", false)
		_ = r.fetchBackups(ctx, c)
		d.alert(ctx, servercheck.AlertInput{Target: r.t, Kind: servercheck.AlertRollbackFailed, Urgent: true, Backups: r.backupList()})
		return r.fail(ctx, ErrServerConnectionLost, "connection lost")
	}
	code := res.Exit
	// php -c exits 0 on ini warnings: for the CLI test, anything PHP says on
	// its error output is a failure (the script cannot tell). The output
	// itself is never kept.
	stderrFail := code == 0 && len(res.Stderr) > 0 && cliTest(r.plan)
	r.scriptSteps(code, stderrFail)
	_ = r.fetchBackups(ctx, c)
	if code != 0 {
		e := exitError(code)
		switch {
		case errors.Is(e, ErrServerRollbackFailed):
			d.alert(ctx, servercheck.AlertInput{Target: r.t, Kind: servercheck.AlertRollbackFailed, Urgent: true, Backups: r.backupList()})
		case errors.Is(e, ErrServerRolledBack):
			d.alert(ctx, servercheck.AlertInput{Target: r.t, Kind: servercheck.AlertRolledBack})
		}
		ferr := r.fail(ctx, e, "exit "+strconv.Itoa(code))
		if errors.Is(e, ErrServerLineMoved) {
			c.Close()
			r.repropose(ctx)
		}
		return ferr
	}
	if err := d.repo().SetState(ctx, a.ID, []State{StateApproved}, StateApplied, ""); err != nil {
		return err
	}
	_ = d.record(ctx, "server_fix.apply", a.ID, "ok", map[string]any{"attempt_id": a.ID, "target_id": r.t.ID, "finding_id": r.sf.FindingID,
		"hash": r.prop.Hash, "scripts_hash": r.b.Hash, "correction_id": r.sf.CorrectionID, "exit": 0, "author": d.approver(a)})
	if stderrFail {
		return r.undo(ctx, c, "php complained")
	}
	if ok, _ := r.checkSite(ctx); !ok {
		return r.undo(ctx, c, "site check failed")
	}
	c.Close()
	return r.prove(ctx)
}

// approver is the actor an attempt was approved by.
func (d Deps) approver(a Attempt) string {
	if a.ApprovedBy != "" {
		return a.ApprovedBy
	}
	return d.actor()
}

func (d Deps) alert(ctx context.Context, in servercheck.AlertInput) {
	if d.Alert != nil {
		d.Alert(ctx, in)
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

// scriptSteps turns the exit status of the apply script into its steps.
// The script runs as a whole, so a failure is placed on the first step
// that can give it: the first step for a refusal before any change, the
// write for a line that moved, the first test, reload or upgrade for a
// failure after the change.
func (r *serverRun) scriptSteps(code int, stderrFail bool) {
	failsAt := func(a serverfix.Action) (bool, string) {
		switch {
		case code == serverfix.ExitNotRoot || code == serverfix.ExitApplied || code == serverfix.ExitLink || code == serverfix.ExitUnsafe:
			return true, detailStopped
		case code == serverfix.ExitLineMoved:
			return a.Op == serverfix.OpSetDirective, detailStopped
		case code == serverfix.ExitRollbackFail:
			return a.Op == serverfix.OpTestConfig || a.Op == serverfix.OpReload || a.Op == serverfix.OpPackageUpgrade, detailRollbackBad
		case code != 0:
			return a.Op == serverfix.OpTestConfig || a.Op == serverfix.OpReload || a.Op == serverfix.OpPackageUpgrade, detailRolledBack
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
		if err := r.d.SiteCheck(ctx, r.t.SiteURL); err != nil {
			r.step(string(serverfix.OpCheckSite), detailSiteDown, false)
			return false, err
		}
		r.step(string(serverfix.OpCheckSite), detailDone, true)
	}
	return true, nil
}

var errNoSiteCheck = errors.New("no site check")

// undo runs the undo script at once (the site broke after the change),
// checks the site again, and ends the attempt failed: rolled back, or with
// an urgent alert and the backups to put back by hand when undo failed.
func (r *serverRun) undo(ctx context.Context, c *sshx.Client, reason string) error {
	d := r.d
	res, err := c.Run(ctx, shArgv(r.b), strings.NewReader(r.b.Undo))
	undone := err == nil && res.Exit == 0
	if undone {
		r.step(StepUndo, detailDone, true)
	} else {
		r.step(StepUndo, detailRollbackBad, false)
	}
	c.Close()
	siteBack := true
	if d.SiteCheck != nil && r.t.SiteURL != "" {
		if err := d.SiteCheck(ctx, r.t.SiteURL); err != nil {
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
	if !undone {
		_ = d.record(ctx, "server_fix.rollback", r.a.ID, "error", ev)
		d.alert(ctx, servercheck.AlertInput{Target: r.t, Kind: servercheck.AlertRollbackFailed, Urgent: true, Backups: r.backupList()})
		_ = d.repo().SetState(ctx, r.a.ID, []State{StateApplied}, StateFailed, d.causeOf(ErrServerRollbackFailed))
		r.saveSteps(ctx)
		r.recollect(ctx)
		return ErrServerRollbackFailed
	}
	_ = d.record(ctx, "server_fix.rollback", r.a.ID, "ok", ev)
	d.alert(ctx, servercheck.AlertInput{Target: r.t, Kind: servercheck.AlertRolledBack, Urgent: !siteBack})
	_ = d.repo().SetState(ctx, r.a.ID, []State{StateApplied}, StateFailed, CauseRolledBack)
	r.saveSteps(ctx)
	r.recollect(ctx)
	return ErrServerRolledBack
}

// recollect checks the server again after a rollback, so the findings
// show the server as it is; its outcome changes nothing of the attempt.
func (r *serverRun) recollect(ctx context.Context) {
	if r.d.CheckServer == nil {
		return
	}
	_, err := r.d.CheckServer(ctx, r.t.ID)
	r.step(StepRecollect, map[bool]string{true: detailDone, false: detailCheckFailed}[err == nil], err == nil)
	r.saveSteps(ctx)
}

// fail ends an attempt that stopped before or during the script (state
// approved or applied → failed) with the cause of e, and returns e.
func (r *serverRun) fail(ctx context.Context, e error, reason string) error {
	d := r.d
	if err := d.repo().SetState(ctx, r.a.ID, []State{StateApproved, StateApplied}, StateFailed, d.causeOf(e)); err != nil {
		return errors.Join(e, err)
	}
	r.saveSteps(ctx)
	_ = d.record(ctx, "server_fix.apply", r.a.ID, "error", map[string]any{"attempt_id": r.a.ID, "target_id": r.t.ID, "finding_id": r.sf.FindingID,
		"hash": r.prop.Hash, "correction_id": r.sf.CorrectionID, "error": serverErrorKey(e), "reason": reason, "backups": len(r.backupList())})
	return e
}

// repropose checks the server again after a line moved since the
// collection and, when the finding is still open, prepares a new fix (a
// new correction id) that waits for the user's approval.
func (r *serverRun) repropose(ctx context.Context) {
	d := r.d
	if d.CheckServer == nil {
		return
	}
	if _, err := d.CheckServer(ctx, r.t.ID); err != nil {
		return
	}
	list, err := scan.NewRepo(d.Store).FindByIDPrefix(ctx, r.sf.FindingID)
	if err != nil || len(list) != 1 || list[0].Status == scan.StatusGone {
		return
	}
	w := ServerWork{TargetID: r.t.ID}
	if r.a.Work.Server != nil {
		w = *r.a.Work.Server
	}
	if na, err := d.proposeServer(ctx, r.t, list[0], w); err == nil {
		_ = d.record(ctx, "server_fix.repropose", na.ID, "ok", map[string]any{"attempt_id": na.ID, "previous_attempt_id": r.a.ID, "target_id": r.t.ID})
	}
}

// backups are the files the bundle backed up, with where each copy lies.
func (r *serverRun) backups() (bak, file []string) {
	dir := backupDir(r.b, r.sf.CorrectionID)
	n := 0
	for _, a := range r.plan.Actions {
		if a.Op == serverfix.OpBackup {
			n++
			bak = append(bak, dir+"/"+strconv.Itoa(n))
			file = append(file, a.Path)
		}
	}
	return bak, file
}

// backupList is "backup -> file" for each backup, for the alert's page.
func (r *serverRun) backupList() []string {
	bak, file := r.backups()
	out := make([]string, len(bak))
	for i := range bak {
		out[i] = bak[i] + " -> " + file[i]
	}
	return out
}

// fetchBackups reads the backups the script made, with the scripts' own
// privilege (sudo -n cat for a root bundle, the SSH user for a .user.ini
// one, from its home), and keeps them encrypted on the workstation. Only
// the fixed paths Michel built are read; a backup that is missing, cut or
// unreadable is skipped. Nothing on the server is ever deleted.
func (r *serverRun) fetchBackups(ctx context.Context, c *sshx.Client) int {
	if c == nil {
		return 0
	}
	repo := r.d.repo()
	have, _ := repo.Backups(ctx, r.a.ID)
	seen := map[string]bool{}
	for _, b := range have {
		seen[b.RemotePath] = true
	}
	bak, _ := r.backups()
	n := 0
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
		if _, err := repo.AddBackup(ctx, ServerBackup{AttemptID: r.a.ID, TargetID: r.t.ID, RemotePath: p, SHA256: hex.EncodeToString(sum[:]), Content: res.Stdout}); err == nil {
			n++
		}
	}
	return n
}

// prove checks the server again after a fix that ran and a site that
// answers: proven_fixed when the check no longer sees the finding, judged
// it fully and the site was checked (when there is one); else
// inconclusive with the cause. A proven preprod fix builds the
// production's.
func (r *serverRun) prove(ctx context.Context) error {
	d := r.d
	lang := d.lang()
	repo := d.repo()
	siteChecked := true
	for _, s := range r.steps {
		if s.Op == string(serverfix.OpCheckSite) && !s.OK {
			siteChecked = false
		}
	}
	if d.CheckServer == nil {
		r.step(StepRecollect, detailCheckFailed, false)
		r.saveSteps(ctx)
		return repo.SetState(ctx, r.a.ID, []State{StateApplied}, StateInconclusive, d.causeOfKey("fix.server.check_failed"))
	}
	res, err := d.CheckServer(ctx, r.t.ID)
	if err != nil {
		r.step(StepRecollect, detailCheckFailed, false)
		r.saveSteps(ctx)
		return repo.SetState(ctx, r.a.ID, []State{StateApplied}, StateInconclusive, d.causeOfKey("fix.server.check_failed"))
	}
	list, err := scan.NewRepo(d.Store).FindByIDPrefix(ctx, r.sf.FindingID)
	if err != nil {
		return err
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
		r.step(StepRecollect, detailProven, true)
		r.saveSteps(ctx)
		if err := repo.SetState(ctx, r.a.ID, []State{StateApplied}, StateProvenFixed, ""); err != nil {
			return err
		}
		_ = d.record(ctx, "server_fix.proven", r.a.ID, "ok", map[string]any{"attempt_id": r.a.ID, "target_id": r.t.ID,
			"finding_id": r.sf.FindingID, "hash": r.prop.Hash, "correction_id": r.sf.CorrectionID, "mitigation": r.sf.Mitigation})
		r.promote(ctx)
		return nil
	case !gone:
		r.step(StepRecollect, detailStillSeen, false)
		r.saveSteps(ctx)
		return repo.SetState(ctx, r.a.ID, []State{StateApplied}, StateInconclusive, i18n.T(lang, "fix.server.still_seen"))
	case !siteChecked:
		r.step(StepRecollect, detailProven, true)
		r.saveSteps(ctx)
		return repo.SetState(ctx, r.a.ID, []State{StateApplied}, StateInconclusive, i18n.T(lang, "fix.server.site_unchecked"))
	default:
		r.step(StepRecollect, detailPartial, false)
		r.saveSteps(ctx)
		return repo.SetState(ctx, r.a.ID, []State{StateApplied}, StateInconclusive, i18n.T(lang, "fix.server.check_partial"))
	}
}

func (d Deps) causeOfKey(key string) string { return i18n.T(d.lang(), key) }

// promote builds the production fix once a preprod fix is proven: from the
// production's own inventory (its paths, versions and services), so a new
// hash, waiting for its own approval.
func (r *serverRun) promote(ctx context.Context) {
	d := r.d
	w := r.a.Work.Server
	if w == nil || w.ProdTargetID == "" {
		return
	}
	pt, err := d.Targets.Get(ctx, w.ProdTargetID)
	if err != nil {
		return
	}
	list, err := scan.NewRepo(d.Store).FindByIDPrefix(ctx, w.ProdFindingID)
	if err != nil || len(list) != 1 || list[0].Status == scan.StatusGone {
		return
	}
	na, err := d.proposeServer(ctx, pt, list[0], ServerWork{TargetID: pt.ID})
	result, ev := "ok", map[string]any{"preprod_attempt_id": r.a.ID, "target_id": pt.ID, "finding_id": w.ProdFindingID}
	if err != nil {
		result, ev["error"] = "error", serverErrorKey(err)
	} else {
		ev["attempt_id"] = na.ID
	}
	_ = d.record(ctx, "server_fix.promote", r.a.ID, result, ev)
}

// AppliedByMe is the user's word that they ran the apply script of an
// approved fix with executor user. Michel fetches the backups it can read,
// checks the site from the workstation and the server again: proven_fixed
// or inconclusive as for Michel's own run. A site that no longer answers
// gives an urgent alert telling the user to run undo now (Michel never
// runs a script it was not allowed to); the attempt then fails.
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
	if err := d.repo().SetState(ctx, a.ID, []State{StateApproved}, StateApplied, ""); err != nil {
		return err
	}
	_ = d.record(ctx, "server_fix.apply", a.ID, "ok", map[string]any{"attempt_id": a.ID, "target_id": r.t.ID, "finding_id": r.sf.FindingID,
		"hash": r.prop.Hash, "correction_id": r.sf.CorrectionID, "executor": "user", "author": d.actor()})
	if c, err := sshx.Dial(ctx, d.SSH, r.t); err == nil {
		r.fetchBackups(ctx, c)
		c.Close()
	}
	r.step("apply", "run by you", true)
	ok, _ := r.checkSite(ctx)
	if !ok {
		d.alert(ctx, servercheck.AlertInput{Target: r.t, Kind: servercheck.AlertUndoNow, Urgent: true, Backups: r.backupList()})
		_ = d.repo().SetState(ctx, a.ID, []State{StateApplied}, StateFailed, d.causeOf(ErrServerSiteDown))
		r.saveSteps(ctx)
		_ = d.record(ctx, "server_fix.apply", a.ID, "error", map[string]any{"attempt_id": a.ID, "target_id": r.t.ID, "error": "fix.server.site_down_user"})
		return ErrServerSiteDown
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
	return simulate(ctx, c, v)
}

// simulate asks the package manager what the upgrade of v would do,
// changing nothing (apt-get -s, dnf --assumeno, apk --simulate), and
// refuses (ErrSimulationRefused) anything but exactly that upgrade: a
// removal, a replacement, an error, another version. The output is read,
// never kept.
func simulate(ctx context.Context, c *sshx.Client, v serverfix.Plan) error {
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
