package fix

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/serverfix"
	"github.com/kvarot/michel/internal/serverrules"
	"github.com/kvarot/michel/internal/target"
)

// OriginServer is the origin of a server fix Michel prepared alone, from its
// own rules (a setting to its advised value, a package to its fixed
// version): no agent took part.
const OriginServer = "michel.server"

// CauseRolledBack is the cause stored on a server fix that was undone after
// a failed step or a site that stopped answering: the server is as before.
// The digest counts it (digest.CauseRolledBack, the same value); the page
// shows fix.server.rolled_back (CauseText).
const CauseRolledBack = "rolled_back"

// BackupRetention is how long the workstation keeps the copies of the server
// backups. The backups on the servers are never deleted by Michel.
const BackupRetention = 90 * 24 * time.Hour

// StepResult is one step of a server fix as Michel saw it run. Op is a
// serverfix op, or undo or recollect for Michel's own steps. Detail is a
// short fixed text of Michel's, never what the server printed.
type StepResult struct {
	Op     string `json:"op"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Steps of Michel's own, after the script.
const (
	StepUndo      = "undo"
	StepRecollect = "recollect"
)

// ServerWork is what an attempt on a server keeps: the server it runs on,
// and for a preprod attempt the production server and finding whose fix is
// built once this one is proven.
type ServerWork struct {
	TargetID      string `json:"target_id"`
	ProdTargetID  string `json:"prod_target_id,omitempty"`
	ProdFindingID string `json:"prod_finding_id,omitempty"`
	// PreprodAttemptID is, for a production fix built once a preprod fix was
	// proven, that preprod attempt: the only proof that opens the level 3
	// rules for this fix.
	PreprodAttemptID string `json:"preprod_attempt_id,omitempty"`
}

// ServerFix is the validated server fix a proposal carries next to its
// scripts. Actions are the actions Validate returned: they are validated
// again against the current inventory, and the scripts rendered again and
// compared by hash, right before anything is sent.
type ServerFix struct {
	TargetID      string             `json:"target_id"`
	FindingID     string             `json:"finding_id"`
	CorrectionID  string             `json:"correction_id"`
	Executor      target.Executor    `json:"executor"`
	Mitigation    bool               `json:"mitigation,omitempty"`
	NeedsSnapshot bool               `json:"needs_snapshot,omitempty"`
	Actions       []serverfix.Action `json:"actions"`
	// Requested are the actions an agent proposed, as it gave them (only
	// the fields of its tool); nil for Michel's own fix. They are what
	// Michel validates again on the production once a preprod fix of the
	// agent is proven. Not covered by the hash: the scripts are.
	Requested []serverfix.Action `json:"requested,omitempty"`
}

// serverHash is the fingerprint the user approves for a server fix: the
// scripts' hash (both scripts and the checks), the server, the correction
// id and who runs it.
func serverHash(bundleHash string, s ServerFix) string {
	h := sha256.New()
	fmt.Fprintf(h, "michel server fix 1\n%s\n%s\n%s\n%s\n", bundleHash, s.TargetID, s.CorrectionID, s.Executor)
	return hex.EncodeToString(h.Sum(nil))
}

// The refusals and outcomes of a server fix, each with a catalog key
// (ErrorKey).
var (
	// ErrNotServerFinding: the finding is not a finding of a server.
	ErrNotServerFinding = errors.New("this finding is not a finding of a server")
	// ErrFindingGone: the last check no longer sees the finding.
	ErrFindingGone = errors.New("the last check of the server no longer sees this finding")
	// ErrNoInventory: the server was never checked.
	ErrNoInventory = errors.New("the server was never checked: check it first")
	// ErrReportOnly: the server's fix level is 0 (report only).
	ErrReportOnly = errors.New("this server is set to report only")
	// ErrNeedsAgent: Michel has no deterministic fix for this finding.
	ErrNeedsAgent = errors.New("Michel has no ready-made fix for this finding")
	// ErrPreprodMissing: the linked preprod server does not show the
	// finding, so the fix cannot be tried there first.
	ErrPreprodMissing = errors.New("the preprod server does not show this finding")
	// ErrSnapshotRequired: a package upgrade needs the user's snapshot.
	ErrSnapshotRequired = errors.New("make a snapshot of the server first")
	// ErrScriptChanged: the scripts are not the ones validated (stored
	// record altered, or the server changed since): nothing was sent.
	ErrScriptChanged = errors.New("the scripts are not the ones that were validated: nothing was sent")
	// ErrSimulationRefused: the package manager's simulation shows a
	// removal, an error or not the expected upgrade: nothing was applied.
	ErrSimulationRefused = errors.New("the package simulation refuses this upgrade: nothing was applied")
	// ErrNotMichelExecutor: Michel does not run this fix (executor user,
	// or root needed without sudo nopasswd).
	ErrNotMichelExecutor = errors.New("Michel does not run this fix: run it yourself")
	// ErrNotUserExecutor: this fix is run by Michel, not by the user.
	ErrNotUserExecutor = errors.New("this fix is run by Michel")
	// The script's own refusals (serverfix exit codes) and outcomes.
	ErrServerWrongUser      = errors.New("the script was run by the wrong user: nothing changed")
	ErrServerAlreadyApplied = errors.New("this correction was already run once: prepare a new one")
	ErrServerLineMoved      = errors.New("the file changed since the check: nothing changed, Michel checks again")
	ErrServerLink           = errors.New("a file is a symbolic link: nothing changed")
	ErrServerUnsafe         = errors.New("a folder or file is not safe: nothing changed")
	ErrServerRollbackFailed = errors.New("the fix failed and could not be undone")
	ErrServerRolledBack     = errors.New("the fix failed and was undone: the server is as before")
	ErrServerSiteDown       = errors.New("the site no longer answers since the fix: run the undo script now")
	// ErrServerUnknownState: the script ran past its bound or its
	// connection dropped; Michel cannot tell what changed.
	ErrServerUnknownState = errors.New("the script gave no answer: Michel cannot tell what changed, look at the server")
	// ErrServerSudoRefused: sudo asked for a password on the server:
	// nothing ran.
	ErrServerSudoRefused = errors.New("sudo refused to run the script without a password: nothing changed")
	// ErrServerNotRun: the shell or sudo could not run the script (exit
	// 126 or 127): nothing ran.
	ErrServerNotRun = errors.New("the script could not be run on the server: nothing changed")
	// ErrServerStopped: the script failed before its first change.
	ErrServerStopped = errors.New("the script stopped before changing anything")
	// ErrPackageFailed: the package upgrade failed; the package may have
	// changed, only the snapshot takes it back.
	ErrPackageFailed = errors.New("the package upgrade failed: restore your snapshot")
	// ErrSiteDownAfterUpgrade: the site no longer answers after a package
	// upgrade; only the snapshot takes it back.
	ErrSiteDownAfterUpgrade = errors.New("the site no longer answers after the package upgrade: restore your snapshot")
)

// Causes stored as codes (CauseText renders them): the digest counts
// CauseRolledBack only, never a package fix's failure.
const (
	CausePackageFailed        = "package_failed"
	CauseSiteDownAfterUpgrade = "site_down_after_upgrade"
	// CauseUserChecked ends a fix of unknown outcome: the user looked at the
	// server themselves and says they know where it stands.
	CauseUserChecked = "user_checked"
)

// serverErrorKey is the catalog key of a server refusal, "" otherwise.
func serverErrorKey(err error) string {
	for _, k := range []struct {
		err error
		key string
	}{
		{ErrNotServerFinding, "fix.server.not_server"},
		{ErrFindingGone, "fix.server.finding_gone"},
		{ErrNoInventory, "fix.server.no_inventory"},
		{ErrReportOnly, "fix.server.report_only"},
		{ErrNeedsAgent, "fix.server.needs_agent"},
		{ErrPreprodMissing, "fix.server.preprod_missing"},
		{ErrSnapshotRequired, "fix.server.snapshot_required"},
		{ErrScriptChanged, "fix.server.script_changed"},
		{ErrSimulationRefused, "fix.server.simulation_refused"},
		{ErrNotMichelExecutor, "fix.server.not_michel"},
		{ErrNotUserExecutor, "fix.server.not_user"},
		{ErrServerWrongUser, "fix.server.wrong_user"},
		{ErrServerAlreadyApplied, "fix.server.already_applied"},
		{ErrServerLineMoved, "fix.server.line_moved"},
		{ErrServerLink, "fix.server.link"},
		{ErrServerUnsafe, "fix.server.unsafe"},
		{ErrServerRollbackFailed, "fix.server.rollback_failed"},
		{ErrServerRolledBack, "fix.server.rolled_back"},
		{ErrServerSiteDown, "fix.server.site_down_user"},
		{ErrServerUnknownState, "fix.server.unknown_state"},
		{ErrServerSudoRefused, "fix.server.sudo_refused"},
		{ErrServerNotRun, "fix.server.not_run"},
		{ErrServerStopped, "fix.server.stopped"},
		{ErrPackageFailed, "fix.server.package_failed"},
		{ErrSiteDownAfterUpgrade, "fix.server.site_down_after_upgrade"},
		{serverfix.ErrUntestableBinary, "fix.server.untestable_binary"},
		{serverfix.ErrMajorUpgrade, "fix.server.major_upgrade"},
		{serverfix.ErrAmbiguous, "fix.server.ambiguous"},
		{serverfix.ErrLinkedFile, "fix.server.link"},
	} {
		if errors.Is(err, k.err) {
			return k.key
		}
	}
	for _, e := range []error{serverfix.ErrPathNotAllowed, serverfix.ErrBadValue, serverfix.ErrUnknownDirective, serverfix.ErrUnknownService,
		serverfix.ErrUnknownPackage, serverfix.ErrBadAction, serverfix.ErrDowngrade, serverfix.ErrNotValidated, serverfix.ErrGrammar} {
		if errors.Is(err, e) {
			return "fix.server.refused"
		}
	}
	return ""
}

// CauseText is the cause of an attempt as the user reads it: the stored
// cause, except CauseRolledBack, kept as a code for the digest.
func CauseText(lang i18n.Lang, cause string) string {
	switch cause {
	case CauseRolledBack:
		return i18n.T(lang, "fix.server.rolled_back")
	case CausePackageFailed:
		return i18n.T(lang, "fix.server.package_failed")
	case CauseSiteDownAfterUpgrade:
		return i18n.T(lang, "fix.server.site_down_after_upgrade")
	case CauseUserChecked:
		return i18n.T(lang, "fix.server.user_checked")
	}
	return cause
}

// causeOf is the cause stored for err: CauseRolledBack, or the text of the
// error's key.
func (d Deps) causeOf(err error) string {
	switch {
	case errors.Is(err, ErrServerRolledBack):
		return CauseRolledBack
	case errors.Is(err, ErrPackageFailed):
		return CausePackageFailed
	case errors.Is(err, ErrSiteDownAfterUpgrade):
		return CauseSiteDownAfterUpgrade
	}
	if k := serverErrorKey(err); k != "" {
		return i18n.T(d.lang(), k)
	}
	return i18n.T(d.lang(), "fix.server.failed")
}

func newCorrectionID() string {
	return ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String()
}

// serverFinding returns the finding with this id (exact or unique prefix)
// and its server.
func (d Deps) serverFinding(ctx context.Context, id string) (scan.Finding, target.Target, error) {
	id = strings.TrimSpace(id)
	list, err := scan.NewRepo(d.Store).FindByIDPrefix(ctx, id)
	if err != nil {
		return scan.Finding{}, target.Target{}, err
	}
	var f scan.Finding
	switch {
	case len(list) == 1:
		f = list[0]
	default:
		found := false
		for _, x := range list {
			if x.ID == id {
				f, found = x, true
			}
		}
		if !found {
			return scan.Finding{}, target.Target{}, fmt.Errorf("%w: no single finding has the id %q", ErrNotFound, scan.SanitizeText(id))
		}
	}
	if f.Kind != scan.KindServerConfig && f.Kind != scan.KindServerPackage {
		return scan.Finding{}, target.Target{}, ErrNotServerFinding
	}
	if d.Targets == nil {
		return scan.Finding{}, target.Target{}, errors.New("the fix service needs the server registry")
	}
	t, err := d.Targets.Get(ctx, f.ProjectID)
	if err != nil {
		return scan.Finding{}, target.Target{}, err
	}
	return f, t, nil
}

// IsServerFinding tells whether the finding id names a finding of a server
// (the API and the CLI route Start to StartServer with it).
func IsServerFinding(ctx context.Context, d Deps, findingID string) bool {
	_, _, err := d.serverFinding(ctx, findingID)
	return err == nil
}

// StartServer prepares Michel's own fix of a server finding and proposes
// it: no agent, no SSH write. The plan comes from the rule (a setting to
// its advised value) or the advisory (a package to its fixed version); a
// package upgrade is simulated over SSH first and refused when the package
// manager would remove or replace anything. ErrNeedsAgent when Michel has
// no deterministic fix. When the server has a preprod, the fix is prepared
// for the preprod first (ErrPreprodMissing when the preprod does not show
// the finding); the production fix is built from the production's own
// inventory once the preprod one is proven. The attempt is returned in
// state proposed and waits for the user's approval.
func StartServer(ctx context.Context, d Deps, findingID string) (Attempt, error) {
	f, t, err := d.serverFinding(ctx, findingID)
	if err != nil {
		return Attempt{}, err
	}
	if t.FixLevel == 0 {
		return Attempt{}, ErrReportOnly
	}
	if f.Status == scan.StatusGone {
		return Attempt{}, ErrFindingGone
	}
	if t.PreprodID == "" {
		return d.proposeServer(ctx, t, f, ServerWork{TargetID: t.ID})
	}
	pt, err := d.Targets.Get(ctx, t.PreprodID)
	if err != nil {
		return Attempt{}, fmt.Errorf("cannot read the preprod server: %w", err)
	}
	if pt.FixLevel == 0 {
		return Attempt{}, ErrReportOnly
	}
	pf, ok, err := d.sameOn(ctx, pt, f)
	if err != nil {
		return Attempt{}, err
	}
	if !ok {
		return Attempt{}, ErrPreprodMissing
	}
	return d.proposeServer(ctx, pt, pf, ServerWork{TargetID: pt.ID, ProdTargetID: t.ID, ProdFindingID: f.ID})
}

// sameOn finds on server t the open finding that is f's (same advisory or
// rule, package and SAPI); paths and binaries may differ between servers.
func (d Deps) sameOn(ctx context.Context, t target.Target, f scan.Finding) (scan.Finding, bool, error) {
	list, err := scan.NewRepo(d.Store).ListServerFindings(ctx, t.ID)
	if err != nil {
		return scan.Finding{}, false, err
	}
	var hit []scan.Finding
	for _, x := range list {
		if x.Status != scan.StatusGone && x.Kind == f.Kind && x.Ecosystem == f.Ecosystem && x.Package == f.Package && x.OSVID == f.OSVID && x.SAPI == f.SAPI {
			hit = append(hit, x)
		}
	}
	if len(hit) != 1 {
		return scan.Finding{}, false, nil
	}
	return hit[0], true, nil
}

// proposeServer builds, validates and renders the fix of f on t, then
// stores the attempt and its proposal (state proposed).
func (d Deps) proposeServer(ctx context.Context, t target.Target, f scan.Finding, w ServerWork) (Attempt, error) {
	return d.proposeServerAs(ctx, t, f, w, OriginServer, nil)
}

// proposeAgain prepares again, on server t for its finding f, the fix of
// attempt a: Michel's own plan for Michel's fix; for an agent's fix, the
// actions the agent asked for, validated against t's own inventory (as
// given, else with Michel locating each directive itself when the files
// differ from the server the agent saw). The new attempt keeps a's origin:
// an agent's fix is never applied by a rule.
func (d Deps) proposeAgain(ctx context.Context, a Attempt, sf ServerFix, t target.Target, f scan.Finding, w ServerWork) (Attempt, error) {
	if !agentOrigin(a.Origin) {
		return d.proposeServer(ctx, t, f, w)
	}
	if len(sf.Requested) == 0 {
		return Attempt{}, ErrNeedsAgent
	}
	na, err := d.proposeServerAs(ctx, t, f, w, a.Origin, sf.Requested)
	if err == nil || errors.Is(err, ErrBusy) {
		return na, err
	}
	located := make([]serverfix.Action, len(sf.Requested))
	changed := false
	for i, x := range sf.Requested {
		if x.Op == serverfix.OpSetDirective && x.Path != "" {
			x.Path, changed = "", true
		}
		located[i] = x
	}
	if !changed {
		return Attempt{}, err
	}
	return d.proposeServerAs(ctx, t, f, w, a.Origin, located)
}

// proposeServerAs is proposeServer for an origin: Michel's own plan when
// requested is nil, else the requested actions (an agent's).
func (d Deps) proposeServerAs(ctx context.Context, t target.Target, f scan.Finding, w ServerWork, origin string, requested []serverfix.Action) (Attempt, error) {
	inv, ok, err := d.Targets.LatestInventory(ctx, t.ID)
	if err != nil {
		return Attempt{}, err
	}
	if !ok {
		return Attempt{}, ErrNoInventory
	}
	var plan serverfix.Plan
	if requested == nil {
		if plan, err = planFor(f, t, inv); err != nil {
			return Attempt{}, err
		}
	} else {
		if healthTarget(t) {
			return Attempt{}, ErrHealthForbidden
		}
		plan = serverfix.Plan{TargetID: t.ID, FindingID: f.ID, Mitigation: f.Mitigation, Actions: requested}
	}
	v, err := serverfix.Validate(plan, t, inv)
	if err != nil {
		return Attempt{}, err
	}
	if busy, err := d.busy(ctx, t.ID); err != nil {
		return Attempt{}, err
	} else if busy {
		return Attempt{}, ErrBusy
	}
	if v.NeedsSnapshot {
		if err := d.simulateOnce(ctx, t, v); err != nil {
			_ = d.record(ctx, "server_fix.propose", t.ID, "refused", map[string]any{"target_id": t.ID, "finding_id": f.ID, "reason": "simulation"})
			return Attempt{}, err
		}
	}
	cid := newCorrectionID()
	b, err := serverfix.Render(v, t, cid)
	if err != nil {
		return Attempt{}, err
	}
	sf := ServerFix{TargetID: t.ID, FindingID: f.ID, CorrectionID: cid, Executor: executorFor(t, b),
		Mitigation: v.Mitigation, NeedsSnapshot: v.NeedsSnapshot, Actions: v.Actions, Requested: requested}
	repo := d.repo()
	a, err := repo.CreateAttempt(ctx, Attempt{FindingID: f.ID, ProjectID: t.ID, Origin: origin, Work: Work{Server: &w}})
	if err != nil {
		return Attempt{}, err
	}
	lang := d.lang()
	prop := Proposal{AttemptID: a.ID, Summary: summaryOf(lang, t, sf), StepsServer: explainServer(lang, t, sf, b),
		Scripts: &b, Server: &sf, Hash: serverHash(b.Hash, sf)}
	if prop, err = repo.AddProposal(ctx, prop); err != nil {
		_ = repo.SetState(ctx, a.ID, []State{StatePreparing}, StateFailed, d.causeOf(err))
		return Attempt{}, err
	}
	if err := repo.SetState(ctx, a.ID, []State{StatePreparing}, StateProposed, ""); err != nil {
		return Attempt{}, err
	}
	if err := d.record(ctx, "server_fix.propose", a.ID, "ok", map[string]any{
		"attempt_id": a.ID, "target_id": t.ID, "finding_id": f.ID, "proposal_id": prop.ID, "correction_id": cid,
		"hash": prop.Hash, "scripts_hash": b.Hash, "executor": string(sf.Executor), "run_as_root": b.RunAsRoot,
		"needs_snapshot": sf.NeedsSnapshot, "mitigation": sf.Mitigation, "preprod_first": w.ProdTargetID != "", "origin": origin,
	}); err != nil {
		return Attempt{}, err
	}
	if d.Notify != nil {
		d.Notify(ctx, 1)
	}
	return repo.GetAttempt(ctx, a.ID)
}

// executorFor says who runs the scripts: Michel only when the server says
// so and, for a root bundle, sudo needs no password; the user otherwise.
func executorFor(t target.Target, b serverfix.Bundle) target.Executor {
	if t.Executor == target.ExecMichel && (!b.RunAsRoot || t.Sudo == target.SudoNopasswd) {
		return target.ExecMichel
	}
	return target.ExecUser
}

// locationFile is the file of a finding's location "file:line".
func locationFile(loc string) string {
	if i := strings.LastIndexByte(loc, ':'); i > 0 {
		if _, err := strconv.Atoi(loc[i+1:]); err == nil {
			return loc[:i]
		}
	}
	return loc
}

// planFor is Michel's own plan for f, or ErrNeedsAgent.
func planFor(f scan.Finding, t target.Target, inv target.Inventory) (serverfix.Plan, error) {
	p := serverfix.Plan{TargetID: t.ID, FindingID: f.ID, Mitigation: f.Mitigation}
	switch f.Kind {
	case scan.KindServerConfig:
		set, err := serverrules.Rules()
		if err != nil {
			return serverfix.Plan{}, err
		}
		var rule *serverrules.ConfigRule
		for i := range set.Config {
			if set.Config[i].ID == f.OSVID {
				rule = &set.Config[i]
			}
		}
		if rule == nil || rule.Advised == "" || rule.Directive != f.Package {
			return serverfix.Plan{}, ErrNeedsAgent
		}
		sapi, file := f.SAPI, locationFile(f.Location)
		switch {
		case path.Base(file) == ".user.ini":
			sapi = serverfix.SAPIUserIni
		case file == "":
			// The directive is set nowhere: its line goes at the end of the
			// php.ini this runtime loads.
			bin := strings.TrimPrefix(f.ManifestRelPath, f.SAPI+":")
			for _, rt := range inv.PHP {
				if rt.SAPI == f.SAPI && rt.Binary == bin {
					file = rt.LoadedIni
				}
			}
		}
		if file == "" {
			return serverfix.Plan{}, ErrNeedsAgent
		}
		p.Actions = []serverfix.Action{{Op: serverfix.OpSetDirective, Directive: rule.Directive, Value: rule.Advised, SAPI: sapi, Path: file}}
		return p, nil
	case scan.KindServerPackage:
		if f.Ecosystem != "os" || len(f.FixedVersions) == 0 || f.FixedVersions[0] == "" {
			return serverfix.Plan{}, ErrNeedsAgent
		}
		pkg := packageFor(inv, f.Package)
		if pkg == "" {
			return serverfix.Plan{}, ErrNeedsAgent
		}
		p.Actions = []serverfix.Action{{Op: serverfix.OpPackageUpgrade, Package: pkg, Version: f.FixedVersions[0]}}
		return p, nil
	}
	return serverfix.Plan{}, ErrNotServerFinding
}

// packageFor is the installed package to upgrade for an advisory on the
// source package src: that very package, or the only one built from it.
// Several binary packages mean several upgrades, which is not a one-package
// fix: "".
func packageFor(inv target.Inventory, src string) string {
	var built []string
	for _, p := range inv.Packages {
		if p.Name == src {
			return src
		}
		if p.Source == src {
			built = append(built, p.Name)
		}
	}
	if len(built) == 1 {
		return built[0]
	}
	return ""
}

// backupDir is where the scripts keep their backups on the server.
func backupDir(b serverfix.Bundle, correctionID string) string {
	if b.RunAsRoot {
		return serverfix.RootBackups + "/" + correctionID
	}
	return "~/.michel/backups/" + correctionID
}

// summaryOf is the one line that names the fix.
func summaryOf(lang i18n.Lang, t target.Target, sf ServerFix) string {
	name := scan.SanitizeText(t.Name)
	for _, a := range sf.Actions {
		switch a.Op {
		case serverfix.OpSetDirective:
			return i18n.T(lang, "fix.server.summary_set", a.Directive, a.Value, name)
		case serverfix.OpPackageUpgrade:
			return i18n.T(lang, "fix.server.summary_package", a.Package, a.Version, name)
		}
	}
	return i18n.T(lang, "fix.server.summary", name)
}

// explainServer says in plain words, in the user's language, what the
// scripts do, step by step, then who runs them and how to undo.
func explainServer(lang i18n.Lang, t target.Target, sf ServerFix, b serverfix.Bundle) []string {
	dir := backupDir(b, sf.CorrectionID)
	var out []string
	n := 0
	for _, a := range sf.Actions {
		switch a.Op {
		case serverfix.OpBackup:
			n++
			out = append(out, i18n.T(lang, "fix.server.explain.backup", a.Path, dir+"/"+strconv.Itoa(n)))
		case serverfix.OpSetDirective:
			if a.Append {
				out = append(out, i18n.T(lang, "fix.server.explain.append", a.Key, a.Value, a.Path))
			} else {
				out = append(out, i18n.T(lang, "fix.server.explain.set", a.Key, a.Value, a.Path, a.Line))
			}
		case serverfix.OpTestConfig:
			if a.SAPI == serverfix.SAPIFPM {
				out = append(out, i18n.T(lang, "fix.server.explain.test_fpm"))
			} else {
				out = append(out, i18n.T(lang, "fix.server.explain.test_cli", a.Path))
			}
		case serverfix.OpReload:
			out = append(out, i18n.T(lang, "fix.server.explain.reload", a.Service))
		case serverfix.OpPackageUpgrade:
			out = append(out, i18n.T(lang, "fix.server.explain.package", a.Package, a.Version))
		case serverfix.OpCheckSite:
			out = append(out, i18n.T(lang, "fix.server.explain.check_site"))
		}
	}
	out = append(out, i18n.T(lang, "fix.server.explain.recollect"))
	if b.RunAsRoot {
		out = append(out, i18n.T(lang, "fix.server.explain.root"))
	} else {
		out = append(out, i18n.T(lang, "fix.server.explain.user", scan.SanitizeText(t.User)))
	}
	out = append(out, i18n.T(lang, "fix.server.explain.no_link"), i18n.T(lang, "fix.server.explain.trap"))
	if sf.NeedsSnapshot {
		out = append(out, i18n.T(lang, "fix.server.explain.undo_snapshot"))
	} else {
		out = append(out, i18n.T(lang, "fix.server.explain.undo"))
	}
	if sf.Mitigation {
		out = append(out, i18n.T(lang, "fix.server.explain.mitigation"))
	}
	if sf.Executor == target.ExecMichel {
		out = append(out, i18n.T(lang, "fix.server.explain.executor_michel"))
	} else {
		out = append(out, i18n.T(lang, "fix.server.explain.executor_user"))
	}
	return out
}

// SnapshotDone records the user's word that a snapshot of the server was
// made before the package upgrade of the attempt (audit
// server_fix.snapshot_done, dated). Approve refuses such a fix without it.
func SnapshotDone(ctx context.Context, d Deps, attemptID, actor string) error {
	repo := d.repo()
	a, err := repo.GetAttempt(ctx, attemptID)
	if err != nil {
		return err
	}
	if a.Work.Server == nil {
		return ErrNotServerFinding
	}
	if a.State != StateProposed && a.State != StateApproved {
		return fmt.Errorf("%w (the attempt is %s)", ErrBadTransition, a.State)
	}
	if actor == "" {
		actor = d.actor()
	}
	if err := repo.AckSnapshot(ctx, attemptID, actor); err != nil {
		return err
	}
	return d.record(ctx, "server_fix.snapshot_done", attemptID, "ok", map[string]any{
		"attempt_id": attemptID, "target_id": a.ProjectID, "finding_id": a.FindingID, "author": actor,
	})
}

// approveServer is Approve for a server fix: the hash is the proposal's,
// a package upgrade needs the snapshot acknowledged.
func (d Deps) approveServer(ctx context.Context, a Attempt, prop Proposal, hash string) error {
	repo := d.repo()
	// A rule never approves an agent's fix: the user alone does.
	if d.actor() == ActorAuto && agentOrigin(a.Origin) {
		_ = d.record(ctx, "server_fix.approve", a.ID, "refused", map[string]any{"attempt_id": a.ID, "reason": "agent fix approved by a rule"})
		return fmt.Errorf("%w: an agent's fix is approved by the user only", ErrBadTransition)
	}
	if hash == "" || prop.Hash != hash {
		_ = d.record(ctx, "server_fix.approve", a.ID, "refused", map[string]any{"attempt_id": a.ID, "reason": "stale proposal", "current_hash": prop.Hash})
		return ErrStaleProposal
	}
	if prop.Server == nil || prop.Scripts == nil {
		return ErrScriptChanged
	}
	if prop.Server.NeedsSnapshot {
		_, _, ok, err := repo.SnapshotAck(ctx, a.ID)
		if err != nil {
			return err
		}
		if !ok {
			_ = d.record(ctx, "server_fix.approve", a.ID, "refused", map[string]any{"attempt_id": a.ID, "reason": "snapshot required", "hash": prop.Hash})
			return ErrSnapshotRequired
		}
	}
	if err := repo.Approve(ctx, a.ID, d.actor(), prop.ID, prop.Hash); err != nil {
		return err
	}
	return d.record(ctx, "server_fix.approve", a.ID, "ok", map[string]any{
		"attempt_id": a.ID, "target_id": a.ProjectID, "finding_id": a.FindingID, "proposal_id": prop.ID, "hash": prop.Hash,
		"correction_id": prop.Server.CorrectionID, "executor": string(prop.Server.Executor), "author": d.actor(),
	})
}

// PurgeServerBackups deletes the workstation copies of server backups older
// than BackupRetention; it returns how many. The servers keep theirs.
func PurgeServerBackups(ctx context.Context, d Deps) (int, error) {
	return d.repo().PurgeBackups(ctx, d.now().Add(-BackupRetention))
}

// ResolveUnknown is the way out of a fix of unknown outcome: the user checked
// the server themselves, and the attempt ends failed with the cause
// CauseUserChecked (audited server_fix.resolved). Michel changes nothing on
// the server. Only an attempt in state unknown can be resolved
// (ErrBadTransition otherwise), and only a server fix (ErrNotServerFinding).
func ResolveUnknown(ctx context.Context, d Deps, attemptID, actor string) error {
	repo := d.repo()
	a, err := repo.GetAttempt(ctx, attemptID)
	if err != nil {
		return err
	}
	if a.Work.Server == nil {
		return ErrNotServerFinding
	}
	if actor == "" {
		actor = d.actor()
	}
	if err := repo.SetState(ctx, a.ID, []State{StateUnknown}, StateFailed, CauseUserChecked); err != nil {
		return err
	}
	return d.record(ctx, "server_fix.resolved", a.ID, "ok", map[string]any{
		"attempt_id": a.ID, "target_id": a.ProjectID, "finding_id": a.FindingID, "author": actor,
	})
}
