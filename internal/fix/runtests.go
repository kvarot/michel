package fix

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

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
	// ErrTestsRunning: this process already runs the tests of the attempt
	// on a click; a second click runs nothing.
	ErrTestsRunning = errors.New("the tests of this attempt are already running")
)

// DefaultTestsTimeout bounds a run of the tests a person asked for (install
// and tests) when Deps.TestsTimeout is 0.
const DefaultTestsTimeout = 30 * time.Minute

// TestsTimeout is the bound of a run of the tests a person asked for.
func (d Deps) TestsTimeout() time.Duration {
	if d.TestsBound > 0 {
		return d.TestsBound
	}
	return DefaultTestsTimeout
}

// beginTests marks a run of the tests of the attempt in this process; false
// when one already runs.
func (s *Sessions) beginTests(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.testing == nil {
		s.testing = map[string]bool{}
	}
	if s.testing[id] {
		return false
	}
	s.testing[id] = true
	return true
}

func (s *Sessions) endTests(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.testing, id)
}

// CanRunTests reports whether a click may run the tests of p: they wait
// for one, and the tree they would run on is kept.
func CanRunTests(p Proposal) bool {
	return p.TestsStatus == workcopy.TestsAwaiting && p.Tree != "" && p.Server == nil
}

// RunTests runs the project's tests on a person's click, for the current
// proposal of the attempt (state proposed) whose hash is hash and whose
// tests wait (ErrStaleProposal, ErrNotAwaiting, ErrNoTree, ErrBadTransition
// otherwise: nothing runs; ErrTestsRunning while this process runs them
// already). Michel materialises the proposal's tree in a scratch folder of
// its own, installs, runs the tests (all bounded by TestsTimeout), and
// records a new proposal with the same change, commit, tree and re-scan and
// the tests' result, which supersedes the clicked one only if that one is
// still current (ErrStaleProposal otherwise: the result is dropped). The
// agent's session goes on; no waiting notification is sent. Every click is
// in the audit log (fix.tests_run).
func RunTests(ctx context.Context, d Deps, attemptID, hash string) (Proposal, error) {
	ctx, cancel := context.WithTimeout(ctx, d.TestsTimeout())
	defer cancel()
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
	// What Michel says and records holds even when ctx was cut.
	keep := context.WithoutCancel(ctx)
	files := reviewFiles(prop.Files)
	evidence := map[string]any{"attempt_id": attemptID, "proposal_id": prop.ID, "hash": hash, "author": d.actor(), "files_code": len(files)}
	record := func(result string, extra map[string]any) error {
		ev := map[string]any{}
		for k, v := range evidence {
			ev[k] = v
		}
		for k, v := range extra {
			ev[k] = v
		}
		return d.record(keep, "fix.tests_run", attemptID, result, ev)
	}
	refuse := func(reason string, err error) (Proposal, error) {
		_ = record("refused", map[string]any{"reason": reason})
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
	if !d.sessions().beginTests(attemptID) {
		return refuse("already running", ErrTestsRunning)
	}
	defer d.sessions().endTests(attemptID)

	c := a.Work.Copy
	m := mask.New()
	dirs := []string{c.Dir, c.Mirror, d.DataDir}
	tell := func(text string) string { return shown(m, dirs, text) }
	say := func(text string) {
		_, _ = repo.AddMessage(keep, Message{AttemptID: attemptID, Role: RoleMichel, Text: tell(text)})
	}
	// fail is any failure past the checks: said, recorded, nothing stored.
	fail := func(err error) (Proposal, error) {
		say(i18n.T(lang, "fix.msg.tests_error", tell(noPath(err).Error())))
		_ = record("error", map[string]any{"detail": auditDetail(d, err)})
		return Proposal{}, err
	}
	_, p, err := d.find(ctx, a.FindingID)
	if err != nil {
		return fail(err)
	}
	if c.Dir == "" {
		return fail(errors.New("the attempt has no work copy"))
	}
	if d.Gateway == nil {
		return fail(errors.New("the fix service needs the egress gateway"))
	}
	wd := d.work()
	run, cleanup, err := workcopy.MaterializeTests(ctx, wd, c, prop.Tree)
	if err != nil {
		return fail(err)
	}
	defer cleanup()
	proxyURL, closeProxy, err := allowproxy.Listen(d.Gateway, policy.PurposeFixInstall)
	if err != nil {
		return fail(err)
	}
	defer closeProxy()
	wd.ProxyAddr = proxyURL
	dirs = append(dirs, run.Dir)
	// The proposal may have changed while the files were written: nothing
	// runs for a proposal no longer shown.
	if cur, ok, err := repo.CurrentProposal(ctx, attemptID); err != nil {
		return fail(err)
	} else if !ok || cur.Hash != hash {
		return refuse("stale proposal", ErrStaleProposal)
	}
	plan := a.Work.Plan
	status, out := workcopy.TestsNotRun, ""
	var lines []string
	commands := append([]RanCommand{}, prop.Commands...)
	installed := false
	_ = record("started", nil)
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
		_ = record("interrupted", map[string]any{"tests": status})
		return Proposal{}, fmt.Errorf("%w: %v", ErrTestsInterrupted, ctx.Err())
	}
	cleanup()
	next := prop
	next.ID = ""
	next.TestsStatus, next.TestsOutput, next.Commands = status, tell(out), commands
	next.Hash = proposalHash(prop.DiffRaw, prop.CommitSHA, status, prop.Summary)
	evidence["tests"] = status
	got, err := repo.AddProposalIfCurrent(ctx, next, hash)
	switch {
	case errors.Is(err, ErrStaleProposal) || errors.Is(err, ErrBadTransition):
		say(i18n.T(lang, "fix.msg.tests_dropped"))
		_ = record("dropped", nil)
		return Proposal{}, err
	case err != nil:
		return fail(err)
	}
	say(strings.Join(append([]string{i18n.T(lang, "fix.msg.tests_clicked")}, lines...), "\n"))
	if err := record("ok", map[string]any{"proposal_id": got.ID, "new_hash": got.Hash, "clicked_proposal_id": prop.ID}); err != nil {
		// The new proposal is stored and shown: the click succeeded.
		log.Printf("michel: the audit log did not take fix.tests_run for attempt %s: %v", attemptID, noPath(err))
	}
	return got, nil
}
