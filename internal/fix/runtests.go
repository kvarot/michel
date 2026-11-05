package fix

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kvarot/michel/internal/egress/allowproxy"
	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/mask"
	"github.com/kvarot/michel/internal/policy"
	"github.com/kvarot/michel/internal/workcopy"
)

var (
	// ErrNotAwaiting: the current proposal's tests do not wait for a click
	// (they ran, or cannot run). A run a click gave is not run again: the
	// agent can propose again.
	ErrNotAwaiting = errors.New("the tests of this proposal do not wait for a click")
	// ErrNoTree: the proposal was written before Michel kept the tree it was
	// built from; its tests cannot be run on a click.
	ErrNoTree = errors.New("this proposal does not keep the files it was built from")
	// ErrTestsInterrupted: the run of the tests a person asked for was cut
	// (time limit, Ctrl+C): nothing was recorded, the tests still wait.
	ErrTestsInterrupted = errors.New("the run of the tests was interrupted")
)

// CodeFiles are the files of the proposal p of attempt a that are neither
// its plan's manifest nor its lockfile: what running the tests would run
// of the agent's own writing.
func CodeFiles(a Attempt, p Proposal) []string {
	return codeFiles(a.Work.Plan, p.Files)
}

// CanRunTests reports whether a click may run the tests of p: they wait
// for one, and the tree they would run on is kept.
func CanRunTests(p Proposal) bool {
	return p.TestsStatus == workcopy.TestsAwaiting && p.Tree != "" && p.Server == nil
}

// RunTests runs the project's tests on a person's click, for the current
// proposal of the attempt (state proposed) whose hash is hash and whose
// tests wait (ErrStaleProposal, ErrNotAwaiting, ErrNoTree, ErrBadTransition
// otherwise: nothing runs). Michel materialises the proposal's tree in a
// scratch folder of its own, installs, runs the tests, and records a new
// proposal with the same change, commit, tree and re-scan and the tests'
// result, which supersedes the clicked one only if that one is still
// current (ErrStaleProposal otherwise: the result is dropped). The agent's
// session goes on; no waiting notification is sent.
func RunTests(ctx context.Context, d Deps, attemptID, hash string) (Proposal, error) {
	repo := d.repo()
	lang := d.lang()
	a, err := repo.GetAttempt(ctx, attemptID)
	if err != nil {
		return Proposal{}, err
	}
	if a.State != StateProposed {
		return Proposal{}, fmt.Errorf("%w (the attempt is %s)", ErrBadTransition, a.State)
	}
	prop, ok, err := repo.CurrentProposal(ctx, attemptID)
	if err != nil {
		return Proposal{}, err
	}
	if !ok {
		return Proposal{}, ErrNoProposal
	}
	refuse := func(reason string, err error) (Proposal, error) {
		_ = d.record(ctx, "fix.tests_run", attemptID, "refused", map[string]any{
			"attempt_id": attemptID, "proposal_id": prop.ID, "hash": hash, "author": d.actor(), "reason": reason,
		})
		return Proposal{}, err
	}
	switch {
	case hash == "" || prop.Hash != hash:
		return refuse("stale proposal", ErrStaleProposal)
	case prop.TestsStatus != workcopy.TestsAwaiting || a.Work.Server != nil:
		return refuse("tests not awaiting", ErrNotAwaiting)
	case prop.Tree == "":
		return refuse("no tree", ErrNoTree)
	}
	_, p, err := d.find(ctx, a.FindingID)
	if err != nil {
		return Proposal{}, err
	}
	c := a.Work.Copy
	if c.Dir == "" {
		return Proposal{}, errors.New("the attempt has no work copy")
	}
	if d.Gateway == nil {
		return Proposal{}, errors.New("the fix service needs the egress gateway")
	}
	m := mask.New()
	dirs := []string{c.Dir, c.Mirror, d.DataDir}
	tell := func(text string) string { return shown(m, dirs, text) }
	// What Michel says and records holds even when ctx was cut.
	keep := context.WithoutCancel(ctx)
	say := func(text string) {
		_, _ = repo.AddMessage(keep, Message{AttemptID: attemptID, Role: RoleMichel, Text: tell(text)})
	}
	code := codeFiles(a.Work.Plan, prop.Files)
	evidence := map[string]any{"attempt_id": attemptID, "proposal_id": prop.ID, "hash": hash, "author": d.actor(), "files_code": len(code)}

	wd := d.work()
	run, cleanup, err := workcopy.MaterializeTests(ctx, wd, c, prop.Tree)
	if err != nil {
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
	plan := a.Work.Plan
	status, out := workcopy.TestsNotRun, ""
	var lines []string
	commands := append([]RanCommand{}, prop.Commands...)
	installed := false
	var cmdErr *workcopy.CmdError
	switch err := workcopy.Install(ctx, wd, run, plan.Ecosystem, plan.ManifestRel); {
	case err == nil:
		installed = true
	case errors.Is(err, workcopy.ErrInstallUnsupported):
		lines = append(lines, i18n.T(lang, "fix.msg.install_unsupported"))
	case errors.As(err, &cmdErr):
		status, out = workcopy.TestsFailed, cmdErr.Output
		lines = append(lines, i18n.T(lang, "fix.msg.install_failed", tell(cmdErr.Output)))
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
		default:
			var terr error
			status, out, terr = workcopy.RunTests(ctx, wd, run, argv)
			commands = append(commands, RanCommand{What: "tests"})
			lines = append(lines, testsText(lang, tell, status, out, terr))
		}
	}
	if ctx.Err() != nil {
		// Cut before its end: no result to record; the tests still wait.
		say(i18n.T(lang, "fix.msg.tests_interrupted"))
		evidence["tests"] = status
		_ = d.record(keep, "fix.tests_run", attemptID, "interrupted", evidence)
		return Proposal{}, fmt.Errorf("%w: %v", ErrTestsInterrupted, ctx.Err())
	}
	cleanup()
	next := prop
	next.ID = ""
	next.TestsStatus, next.TestsOutput, next.Commands = status, tell(out), commands
	next.Hash = proposalHash(prop.DiffRaw, prop.CommitSHA, status, prop.Summary)
	evidence["tests"] = status
	got, err := repo.AddProposalIfCurrent(ctx, next, hash)
	if err != nil {
		if errors.Is(err, ErrStaleProposal) || errors.Is(err, ErrBadTransition) {
			say(i18n.T(lang, "fix.msg.tests_dropped"))
			_ = d.record(ctx, "fix.tests_run", attemptID, "dropped", evidence)
		}
		return Proposal{}, err
	}
	say(strings.Join(append([]string{i18n.T(lang, "fix.msg.tests_clicked")}, lines...), "\n"))
	evidence["proposal_id"], evidence["new_hash"], evidence["clicked_proposal_id"] = got.ID, got.Hash, prop.ID
	if err := d.record(ctx, "fix.tests_run", attemptID, "ok", evidence); err != nil {
		return got, err
	}
	return got, nil
}
