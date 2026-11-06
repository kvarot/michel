package fix

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kvarot/michel/internal/analyze"
	"github.com/kvarot/michel/internal/brief"
	"github.com/kvarot/michel/internal/egress/allowproxy"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/mask"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/project"
	"github.com/kvarot/michel/internal/scan"
	"github.com/kvarot/michel/internal/workcopy"
)

// Propose records the agent's proposal for the attempt (state preparing or
// proposed; a new proposal supersedes the previous one). Michel freezes one
// snapshot of the copy (a change outside the copy, of an excluded file or
// unreadable ends the attempt: ErrChangeRefused), materialises it in a
// scratch worktree where it installs (with every check of the settings),
// runs the project's tests and re-scans, then commits that very snapshot
// in the mirror; the diff, the files and the hash are the snapshot's. The proposal's
// Hash is the SHA-256 of the raw patch, the commit, the tests status and
// the summary. A change holding a mask token is ErrMaskToken (the attempt
// goes on); an empty change is ErrNoChange. The results come back as a
// message of Michel. The proposal is approved at once when the project's
// level 3 rules allow it and the committed tree is the one Michel's own
// update left (Work.Tree0): the agent changed nothing.
func Propose(ctx context.Context, d Deps, attemptID string, in ProposeInput) (Proposal, error) {
	pl := d.sessions().proposeLock(attemptID)
	pl.Lock()
	defer pl.Unlock()
	repo := d.repo()
	lang := d.lang()
	a, err := repo.GetAttempt(ctx, attemptID)
	if err != nil {
		return Proposal{}, err
	}
	if a.State != StatePreparing && a.State != StateProposed {
		return Proposal{}, fmt.Errorf("%w (the attempt is %s)", ErrBadTransition, a.State)
	}
	fi, p, err := d.find(ctx, a.FindingID)
	if err != nil {
		return Proposal{}, err
	}
	c := a.Work.Copy
	if c.Dir == "" {
		return Proposal{}, errors.New("the attempt has no work copy")
	}
	// Propose runs in michel mcp, not in the process of the session that
	// owns the saved table: a fresh masker of its own nonce, never saved
	// (controller ruling 18, final review I8), so that its tokens never
	// collide with the session's. The page never unmasks (ruling 38).
	m := mask.New()
	dirs := []string{c.Dir, c.Mirror, d.DataDir}
	tell := func(text string) string { return shown(m, dirs, text) }
	summary := tell(in.Summary)
	notes := tell(in.Notes)
	say := func(text string) {
		_, _ = repo.AddMessage(ctx, Message{AttemptID: attemptID, Role: RoleMichel, Text: tell(text)})
	}
	fail := func(key string, cause error) (Proposal, error) {
		text := i18n.T(lang, plainCause(key, cause))
		say(text)
		if repo.SetState(ctx, attemptID, []State{StatePreparing, StateProposed}, StateFailed, text) == nil {
			_ = repo.SetCauseDetail(ctx, attemptID, auditDetail(d, cause))
		}
		got, _ := repo.GetAttempt(ctx, attemptID)
		// In michel mcp (where Propose runs for a real agent) no session
		// runs in this process, so this Close does nothing: the process of
		// the session (serve or fix prepare) sees the failed state within a
		// poll (PollInterval) and closes its agent. In-process callers
		// (tests) close it here.
		d.sessions().Close(attemptID)
		d.cleanup(ctx, got, true)
		_ = d.record(ctx, "fix.propose", attemptID, "refused", map[string]any{"attempt_id": attemptID, "finding_id": fi.ID, "reason": key, "detail": auditDetail(d, cause)})
		return Proposal{}, fmt.Errorf("%w: %v", ErrChangeRefused, cause)
	}
	if d.Gateway == nil {
		return Proposal{}, errors.New("the fix service needs the egress gateway")
	}
	if notes != "" {
		_, _ = repo.AddMessage(ctx, Message{AttemptID: attemptID, Role: RoleAgent, Text: i18n.T(lang, "fix.msg.notes", notes)})
	}

	// One frozen snapshot of the agent's copy (controller ruling 37): the
	// install, the tests, the re-scan, the diff, the hash and the commit are
	// all about it; a write to the copy after this instant belongs to the
	// next proposal.
	wd := d.work()
	snap, err := workcopy.Freeze(ctx, wd, c)
	if err != nil {
		if changeRefused(err) {
			return fail("fix.cause.change_refused", err)
		}
		return Proposal{}, err
	}
	ch := snap.Change
	if len(ch.Files) == 0 {
		say(i18n.T(lang, "fix.msg.no_change"))
		return Proposal{}, ErrNoChange
	}
	if mask.HasToken(string(ch.Raw)) {
		say(i18n.T(lang, "fix.msg.mask_token"))
		return Proposal{}, ErrMaskToken
	}
	// Decided now, before anything runs: the agent left Michel's tree as it
	// was.
	unchanged := a.Work.Tree0 != "" && snap.Tree == a.Work.Tree0

	// Michel's own run on the snapshot, in a scratch worktree: never in the
	// agent's copy.
	run, cleanup, err := workcopy.Materialize(ctx, wd, c, snap.Tree)
	if err != nil {
		if changeRefused(err) {
			return fail("fix.cause.change_refused", err)
		}
		return Proposal{}, err
	}
	defer cleanup()
	proxyURL, closeProxy, err := allowproxy.Listen(d.Gateway, policy.PurposeFixInstall)
	if err != nil {
		return Proposal{}, err
	}
	defer closeProxy()
	wd.ProxyAddr = proxyURL
	dirs = append(dirs, run.Dir)
	var lines []string
	plan := a.Work.Plan
	testsStatus, testsOut := workcopy.TestsNotRun, ""
	installed := false
	// commands are the commands Michel ran, for the proposal's details.
	commands := []RanCommand{}
	if a.Work.UpdateRan && len(plan.Update) > 0 {
		commands = append(commands, RanCommand{What: "update", Argv: strings.Join(plan.Update, " ")})
	}
	installRan := RanCommand{What: "install", Argv: strings.Join(workcopy.InstallCommand(plan.ManifestRel), " ")}
	var cmdErr *workcopy.CmdError
	switch err := workcopy.Install(ctx, wd, run, plan.Ecosystem, plan.ManifestRel); {
	case err == nil:
		installed = true
		commands = append(commands, installRan)
	case errors.Is(err, workcopy.ErrInstallUnsupported):
		lines = append(lines, i18n.T(lang, "fix.msg.install_unsupported"))
	case errors.As(err, &cmdErr):
		commands = append(commands, installRan)
		testsStatus, testsOut = workcopy.TestsFailed, cmdErr.Output
		lines = append(lines, i18n.T(lang, "fix.msg.install_failed", tell(cmdErr.Output)))
	case changeRefused(err):
		return fail("fix.cause.change_refused", err)
	default:
		lines = append(lines, i18n.T(lang, "fix.msg.install_refused", tell(noPath(err).Error())))
	}
	if installed {
		argv, err := workcopy.SplitCommand(p.TestCmd)
		switch {
		case err != nil:
			lines = append(lines, i18n.T(lang, "fix.msg.tests_not_run", tell(err.Error())))
		case len(argv) == 0:
			lines = append(lines, i18n.T(lang, "fix.msg.tests_none"))
		case !unchanged:
			// The agent changed Michel's tree: the tests would run code it
			// wrote (a test, a test setting, a package it added). They wait
			// for a person's click (RunTests); the agent is never trusted
			// with this.
			testsStatus = workcopy.TestsAwaiting
			lines = append(lines, awaitingText(lang, tell, attemptID, ch.Files))
		default:
			var terr error
			commands = append(commands, RanCommand{What: "tests"})
			testsStatus, testsOut, terr = workcopy.RunTests(ctx, wd, run, argv)
			if terr != nil && changeRefused(terr) {
				return fail("fix.cause.change_refused", terr)
			}
			lines = append(lines, testsText(lang, tell, testsStatus, testsOut, terr))
		}
	}
	clean := false
	if absent, err := d.rescan(ctx, run.Dir, fi, p); err != nil {
		lines = append(lines, i18n.T(lang, "fix.msg.rescan_failed", tell(noPath(err).Error())))
	} else if clean = absent; clean {
		lines = append(lines, i18n.T(lang, "fix.msg.rescan_clean", scan.SanitizeText(fi.OSVID)))
	} else {
		lines = append(lines, i18n.T(lang, "fix.msg.rescan_dirty", scan.SanitizeText(fi.OSVID)))
	}
	// The scratch worktree has served; the commit comes from the snapshot.
	cleanup()
	message := "fix(deps): update " + plan.Package
	if plan.Target != "" {
		message += " to " + plan.Target
	}
	if plan.Package == "" {
		message = "fix: Michel"
	}
	sha, _, err := workcopy.CommitSnapshot(ctx, wd, c, snap, message)
	if err != nil {
		if changeRefused(err) || errors.Is(err, workcopy.ErrNothingToCommit) {
			return fail("fix.cause.change_refused", err)
		}
		return Proposal{}, err
	}
	risk := 0
	an, hasAn, err := analyze.NewRepo(d.Store).Get(ctx, fi.ID)
	if err != nil {
		return Proposal{}, err
	}
	if hasAn {
		risk = an.Risk.Score
	}
	prop := Proposal{
		AttemptID: attemptID, Summary: summary, Diff: m.Mask(ch.Display), Files: ch.Files,
		TestsStatus: testsStatus, TestsOutput: tell(testsOut), RescanClean: clean, Risk: risk,
		CommitSHA: sha, DiffRaw: ch.Raw, StepsServer: []string{}, Commands: commands, Tree: snap.Tree,
		FromVersion: cleanVersion(fi.InstalledVersion), ToVersion: committedVersion(ctx, wd, c, plan, sha),
	}
	prop.Hash = proposalHash(ch.Raw, sha, testsStatus, summary)
	prop, err = repo.AddProposal(ctx, prop)
	if err != nil {
		return Proposal{}, err
	}
	if a.State == StatePreparing {
		if err := repo.SetState(ctx, attemptID, []State{StatePreparing}, StateProposed, ""); err != nil {
			return Proposal{}, err
		}
	}
	say(strings.Join(append(lines, i18n.T(lang, "fix.msg.proposed")), "\n"))
	if err := d.record(ctx, "fix.propose", attemptID, "ok", map[string]any{
		"attempt_id": attemptID, "finding_id": fi.ID, "project_id": p.ID, "proposal_id": prop.ID, "hash": prop.Hash,
		"commit": sha, "files": len(ch.Files), "tests": testsStatus, "rescan_clean": clean, "risk": risk,
		"superseded": a.State == StateProposed, "tree_unchanged": unchanged, "tests_awaiting": testsStatus == workcopy.TestsAwaiting,
	}); err != nil {
		return prop, err
	}
	if d.Notify != nil {
		if waiting, err := repo.ListAttempts(ctx, "", string(StateProposed)); err == nil {
			d.Notify(ctx, len(waiting))
		}
	}
	if p.FixLevel >= 3 && p.AutoFixMinor {
		reason := ""
		switch {
		case !hasAn:
			reason = "no analysis"
		case !unchanged:
			reason = "the snapshot is not the tree Michel's update left"
		case !AutoApplicable(p, prop, an, effectiveRisk(d.Policy, p)):
			reason = "the level 3 rules are not all met"
		default:
			own, err := michelsOwnCommit(ctx, wd, c, plan, sha)
			if err != nil {
				return prop, err
			}
			if !own {
				reason = "the committed manifest or lockfile is not what Michel's update writes"
			}
		}
		if reason == "" {
			auto := d
			auto.Actor = ActorAuto
			if err := Approve(ctx, auto, attemptID, prop.Hash); err != nil {
				return prop, err
			}
		} else {
			_ = d.record(ctx, "fix.auto", attemptID, "skipped", map[string]any{"attempt_id": attemptID, "reason": reason})
		}
	}
	return prop, nil
}

// testsText is Michel's line about a run of the tests.
func testsText(lang i18n.Lang, tell func(string) string, status, out string, err error) string {
	switch status {
	case workcopy.TestsPassed:
		return i18n.T(lang, "fix.msg.tests_passed")
	case workcopy.TestsFailed:
		return i18n.T(lang, "fix.msg.tests_failed", tell(out))
	}
	reason := ""
	if err != nil {
		reason = tell(noPath(err).Error())
	}
	return i18n.T(lang, "fix.msg.tests_not_run", reason)
}

// reviewText names the changed files as ShownReviewFiles shows them, the
// manifests and lockfiles said for what they are, then "and N more".
func reviewText(lang i18n.Lang, tell func(string) string, list []ReviewFile) string {
	shownFiles, more := ShownReviewFiles(list)
	names := make([]string, 0, len(shownFiles))
	for _, f := range shownFiles {
		name := tell(scan.SanitizeText(f.Path))
		switch f.Kind {
		case FileManifest:
			name = i18n.T(lang, "fix.msg.file_manifest", name)
		case FileLockfile:
			name = i18n.T(lang, "fix.msg.file_lockfile", name)
		}
		names = append(names, name)
	}
	text := strings.Join(names, ", ")
	if more > 0 {
		text += " " + i18n.N(lang, "fix.msg.tests_awaiting_more", more)
	}
	return text
}

// awaitingText is Michel's line when the tests wait for a click: why, and
// every file the agent changed.
func awaitingText(lang i18n.Lang, tell func(string) string, attemptID string, files []string) string {
	return i18n.T(lang, "fix.msg.tests_awaiting", reviewText(lang, tell, reviewFiles(files)), attemptID)
}

// plainConstraint is the only shape of constraint Michel's own update leaves
// in a manifest: a plain semver range (^1.2.5, ~1.2, 1.2.5, >=1.2). No
// alias, path, URL, git, dev- or "as" form.
var plainConstraint = regexp.MustCompile(`^(?:[\^~]|>=)?v?[0-9]+(?:\.[0-9]+){0,2}$`)

// michelsOwnCommit reports whether the proposal commit sha holds, for the
// planned package, exactly what Michel's update command writes: read from
// the commit in the mirror (never from the working tree), the manifest
// gives the package a plain semver constraint, and the lockfile resolves
// it to plan.Target from an https registry.
func michelsOwnCommit(ctx context.Context, wd workcopy.Deps, c workcopy.Copy, plan Plan, sha string) (bool, error) {
	manifest := workcopy.ManifestOf(plan.ManifestRel)
	if manifest == "" || plan.Package == "" || plan.Target == "" {
		return false, nil
	}
	mb, ok, err := workcopy.CommitFile(ctx, wd, c, sha, manifest)
	if err != nil || !ok {
		return false, err
	}
	lb, ok, err := workcopy.CommitFile(ctx, wd, c, sha, plan.ManifestRel)
	if err != nil || !ok {
		return false, err
	}
	return manifestConstraintOK(mb, plan.Ecosystem, plan.Package) && lockResolvesTarget(lb, plan.Ecosystem, plan.Package, plan.Target), nil
}

// manifestConstraintOK reports whether every constraint of pkg in the
// manifest is a plain semver range (and there is at least one).
func manifestConstraintOK(manifest []byte, ecosystem, pkg string) bool {
	var doc map[string]any
	if json.Unmarshal(manifest, &doc) != nil || doc == nil {
		return false
	}
	sections := []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"}
	if ecosystem == "Packagist" {
		sections = []string{"require", "require-dev"}
	}
	found := false
	for _, s := range sections {
		deps, ok := doc[s].(map[string]any)
		if !ok {
			continue
		}
		v, ok := deps[pkg]
		if !ok {
			continue
		}
		found = true
		cons, ok := v.(string)
		if !ok || !plainConstraint.MatchString(cons) || strings.ContainsAny(cons, ":/@") ||
			strings.Contains(cons, "git") || strings.Contains(cons, "file") || strings.Contains(cons, "http") ||
			strings.Contains(cons, "npm:") || strings.Contains(cons, "dev-") || strings.Contains(cons, " as ") {
			return false
		}
	}
	return found
}

// committedVersion is the version of the planned package the fix commit's
// lockfile resolves (read from the commit in the mirror), else the planned
// target; "" when neither is known.
func committedVersion(ctx context.Context, wd workcopy.Deps, c workcopy.Copy, plan Plan, sha string) string {
	if plan.Package != "" && plan.ManifestRel != "" {
		if lock, ok, err := workcopy.CommitFile(ctx, wd, c, sha, plan.ManifestRel); err == nil && ok {
			if v := cleanVersion(lockVersion(lock, plan.Ecosystem, plan.Package)); v != "" {
				return v
			}
		}
	}
	return cleanVersion(plan.Target)
}

// cleanVersion is v without a leading "v", or "" when it is not a plain
// version string.
func cleanVersion(v string) string {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if !planVersionRe.MatchString(v) {
		return ""
	}
	return v
}

// lockVersion is the version a composer.lock (Packagist) or a
// package-lock.json (npm) resolves pkg to; "" when absent or unreadable.
func lockVersion(lock []byte, ecosystem, pkg string) string {
	var doc map[string]any
	if json.Unmarshal(lock, &doc) != nil || doc == nil {
		return ""
	}
	if ecosystem == "Packagist" {
		for _, section := range []string{"packages", "packages-dev"} {
			list, _ := doc[section].([]any)
			for _, e := range list {
				if entry, _ := e.(map[string]any); entry != nil && entry["name"] == pkg {
					v, _ := entry["version"].(string)
					return v
				}
			}
		}
		return ""
	}
	packages, _ := doc["packages"].(map[string]any)
	entry, _ := packages["node_modules/"+pkg].(map[string]any)
	v, _ := entry["version"].(string)
	return v
}

// lockResolvesTarget reports whether the lockfile resolves pkg to exactly
// target, downloaded from an https URL.
func lockResolvesTarget(lock []byte, ecosystem, pkg, target string) bool {
	var doc map[string]any
	if json.Unmarshal(lock, &doc) != nil || doc == nil {
		return false
	}
	sameVersion := func(v any) bool {
		s, ok := v.(string)
		return ok && (s == target || s == "v"+target)
	}
	if ecosystem == "Packagist" {
		found := false
		for _, section := range []string{"packages", "packages-dev"} {
			list, _ := doc[section].([]any)
			for _, e := range list {
				entry, _ := e.(map[string]any)
				if entry == nil || entry["name"] != pkg {
					continue
				}
				dist, _ := entry["dist"].(map[string]any)
				url, _ := dist["url"].(string)
				if !sameVersion(entry["version"]) || !strings.HasPrefix(strings.ToLower(url), "https://") {
					return false
				}
				found = true
			}
		}
		return found
	}
	packages, _ := doc["packages"].(map[string]any)
	entry, _ := packages["node_modules/"+pkg].(map[string]any)
	if entry == nil {
		return false
	}
	resolved, _ := entry["resolved"].(string)
	return sameVersion(entry["version"]) && strings.HasPrefix(strings.ToLower(resolved), "https://")
}

// effectiveRisk is the risk rule of the project: the policy's with its
// overrides.
func effectiveRisk(pol policy.Policy, p project.Project) policy.RiskConfig {
	eff, _ := analyze.EffectiveRisk(pol.Risk, p.RiskOverrides)
	return eff
}

// proposalHash is the fingerprint the user approves.
func proposalHash(raw []byte, sha, tests, summary string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d\x00", len(raw))
	h.Write(raw)
	fmt.Fprintf(h, "\x00%s\x00%s\x00%s", sha, tests, summary)
	return hex.EncodeToString(h.Sum(nil))
}

// rescan reports whether the finding is absent from the copy.
func (d Deps) rescan(ctx context.Context, root string, fi scan.Finding, p project.Project) (bool, error) {
	if d.Rescan != nil {
		return d.Rescan(ctx, root, fi, p)
	}
	findings, err := scan.ScanDir(ctx, scan.Deps{Store: d.Store, Gateway: d.Gateway, Now: d.now, DataDir: d.DataDir},
		root, []string{fi.Ecosystem}, scan.Options{OSVRoot: d.osvRoot(), Exclude: scan.EffectiveExclude(p)})
	if err != nil && !errors.Is(err, scan.ErrScanIncomplete) {
		return false, err
	}
	for _, f := range findings {
		if sameFinding(f, fi) {
			return false, nil
		}
	}
	if err != nil {
		// A lockfile could not be read: absence is not proven.
		return false, err
	}
	return true, nil
}

// sameFinding compares two findings by manifest, ecosystem, package and
// advisory (the copy's findings have no project id).
func sameFinding(a, b scan.Finding) bool {
	norm := func(s string) string { return strings.ToLower(path.Clean(strings.ReplaceAll(s, `\`, "/"))) }
	return norm(a.ManifestRelPath) == norm(b.ManifestRelPath) && a.Ecosystem == b.Ecosystem &&
		strings.EqualFold(a.Package, b.Package) && strings.EqualFold(a.OSVID, b.OSVID)
}

var (
	planPkgRe     = regexp.MustCompile(`^[@A-Za-z0-9][@A-Za-z0-9._/~+-]{0,213}$`)
	planVersionRe = regexp.MustCompile(`^[0-9A-Za-z.+_-]{1,64}$`)
	planDirRe     = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._/-]{0,199}$`)
)

// buildPlan is the closed update command of the finding, from validated
// fields only (controller ruling 33): composer update or require with
// --no-scripts --no-plugins, npm install or update with --ignore-scripts;
// none for yarn, pnpm or an unknown target.
func buildPlan(fi scan.Finding, b brief.Brief) Plan {
	rel := strings.ReplaceAll(fi.ManifestRelPath, `\`, "/")
	plan := Plan{Ecosystem: fi.Ecosystem, ManifestRel: rel, Package: fi.Package, Target: b.Fixed, Jump: b.Jump, Update: []string{}}
	if plan.Target == "" || !planPkgRe.MatchString(fi.Package) || strings.Contains(fi.Package, "..") || !planVersionRe.MatchString(plan.Target) {
		return plan
	}
	dir, base := path.Dir(rel), path.Base(rel)
	if dir != "." && (!planDirRe.MatchString(dir) || !filepath.IsLocal(filepath.FromSlash(dir)) || strings.Contains(dir, "..")) {
		return plan
	}
	var argv []string
	switch {
	case fi.Ecosystem == "Packagist" && base == "composer.lock":
		switch {
		case b.Directness == string(analyze.Transitive):
			argv = []string{"composer", "update", fi.Package, "--with-dependencies"}
		case b.Jump == string(analyze.JumpMajor):
			argv = []string{"composer", "require", fi.Package + ":^" + plan.Target, "--update-with-all-dependencies"}
		default:
			argv = []string{"composer", "update", fi.Package + ":^" + plan.Target, "--with-all-dependencies"}
		}
		argv = append(argv, "--no-scripts", "--no-plugins", "--no-interaction")
		if dir != "." {
			argv = append(argv, "--working-dir="+dir)
		}
	case fi.Ecosystem == "npm" && base == "package-lock.json":
		if b.Directness == string(analyze.Transitive) {
			argv = []string{"npm", "update", fi.Package}
		} else {
			argv = []string{"npm", "install", fi.Package + "@" + plan.Target, "--save-exact"}
		}
		argv = append(argv, "--ignore-scripts", "--no-audit", "--no-fund")
		if dir != "." {
			argv = append(argv, "--prefix", dir)
		}
	default:
		return plan
	}
	plan.Update = argv
	return plan
}
