package fix

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/analyze"
	"github.com/kvarot/michel/internal/workcopy"
)

// approved runs a full attempt and approves its proposal.
func approved(t *testing.T, f *fixture) (Attempt, Proposal) {
	t.Helper()
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	p, ok, _ := f.d.Repo.CurrentProposal(context.Background(), a.ID)
	if !ok {
		t.Fatal("no proposal")
	}
	if err := Approve(context.Background(), f.d, a.ID, p.Hash); err != nil {
		t.Fatal(err)
	}
	return a, p
}

func TestProposalAfterApproveIsRefused(t *testing.T) {
	f := newFixture(t)
	f.consent()
	a, p := approved(t, f)
	got := f.attempt(a.ID)
	if got.ApprovedProposal != p.ID || got.ApprovedHash != p.Hash {
		t.Errorf("approval not bound: %+v", got)
	}
	if _, err := f.d.Repo.AddProposal(context.Background(), Proposal{AttemptID: a.ID, Summary: "late", Hash: strings.Repeat("c", 64)}); !errors.Is(err, ErrBadTransition) {
		t.Errorf("AddProposal on an approved attempt: %v, want ErrBadTransition", err)
	}
	if _, err := Propose(context.Background(), f.d, a.ID, ProposeInput{Summary: "late"}); !errors.Is(err, ErrBadTransition) {
		t.Errorf("Propose on an approved attempt: %v, want ErrBadTransition", err)
	}
	cur, _, _ := f.d.Repo.CurrentProposal(context.Background(), a.ID)
	if cur.ID != p.ID {
		t.Errorf("the current proposal changed to %s", cur.ID)
	}
	if err := Apply(context.Background(), f.d, a.ID); err != nil {
		t.Fatalf("Apply of the approved proposal: %v", err)
	}
	if _, err := f.d.Repo.AddProposal(context.Background(), Proposal{AttemptID: a.ID, Summary: "later", Hash: strings.Repeat("d", 64)}); !errors.Is(err, ErrBadTransition) {
		t.Errorf("AddProposal on an applied attempt: %v, want ErrBadTransition", err)
	}
}

func TestApplyRefusesWhenProposalChangedAfterApprove(t *testing.T) {
	f := newFixture(t)
	f.consent()
	a, p := approved(t, f)
	// A proposal slips in after the approval (a race the state guard
	// normally prevents): the attempt still names the approved one.
	if _, err := f.st.DB().Exec(`UPDATE fix_attempt SET state = 'proposed' WHERE id = ?`, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.Repo.AddProposal(context.Background(), Proposal{AttemptID: a.ID, Summary: "other", Diff: "x", CommitSHA: p.CommitSHA,
		Files: p.Files, TestsStatus: workcopy.TestsPassed, Hash: strings.Repeat("e", 64), DiffRaw: p.DiffRaw}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.DB().Exec(`UPDATE fix_attempt SET state = 'approved' WHERE id = ?`, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := Apply(context.Background(), f.d, a.ID); !errors.Is(err, ErrStaleProposal) {
		t.Fatalf("Apply with a proposal other than the approved one: %v, want ErrStaleProposal", err)
	}
	if ref := gitT(t, f.env, f.proj.Path, "for-each-ref", "refs/heads/michel/"); ref != "" {
		t.Errorf("a branch was created: %s", ref)
	}
	if got := f.attempt(a.ID); got.State != StateApproved {
		t.Errorf("state = %s", got.State)
	}
}

func TestApproveRefusesASupersededProposal(t *testing.T) {
	f := newFixture(t)
	f.consent()
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	old, _, _ := f.d.Repo.CurrentProposal(context.Background(), a.ID)
	// The approval names a proposal that is no longer current.
	if _, err := f.d.Repo.AddProposal(context.Background(), Proposal{AttemptID: a.ID, Summary: "newer", Hash: strings.Repeat("f", 64)}); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Repo.Approve(context.Background(), a.ID, "web", old.ID, old.Hash); !errors.Is(err, ErrStaleProposal) {
		t.Errorf("Approve of a superseded proposal: %v, want ErrStaleProposal", err)
	}
	if got := f.attempt(a.ID); got.State != StateProposed || got.ApprovedBy != "" {
		t.Errorf("after a refused approval: %+v", got)
	}
}

// michelLock is the lockfile Michel's own update writes in the tests.
const michelLock = `{"packages":[{"name":"acme/lib","version":"1.2.5","dist":{"type":"zip","url":"https://api.github.com/repos/acme/lib/zipball/abc"}}]}` + "\n"

// level3 sets the project at level 3 with the auto rule, an analysis with
// a minor jump and a low risk, and a fake composer that rewrites the
// lockfile on update (Michel's own change, at Start).
func level3(t *testing.T, f *fixture) {
	t.Helper()
	p := f.proj
	p.FixLevel, p.AutoFixMinor = 3, true
	f.update(p)
	if err := analyze.NewRepo(f.st).Save(context.Background(), analyze.Analysis{FindingID: f.finding.ID, ProjectID: f.proj.ID,
		Upgrade: analyze.Upgrade{Target: "1.2.5", Jump: analyze.JumpMinor}, Risk: analyze.Risk{Score: 10}}); err != nil {
		t.Fatal(err)
	}
	f.rec.onRun = func(name string, args []string, dir string) {
		if name == "composer" && args[0] == "update" {
			writeFile(t, dir, "composer.lock", michelLock)
		}
	}
}

// proposeOnly is an agent that changes nothing and proposes.
func proposeOnly(f *fixture) {
	f.agentAct = func(ctx context.Context, d Deps, id, dir string) {
		if _, err := Propose(ctx, d, id, ProposeInput{Summary: "Michel's update looks fine."}); err != nil {
			f.t.Errorf("Propose: %v", err)
		}
	}
}

func TestAutoAppliesMichelsOwnUpdate(t *testing.T) {
	f := newFixture(t)
	f.consent()
	level3(t, f)
	proposeOnly(f)
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	got := f.attempt(a.ID)
	if got.State != StateApplied {
		t.Fatalf("state = %s (%s), want applied by the automatic rule", got.State, got.Cause)
	}
	if got.ApprovedBy != ActorAuto || got.Work.Tree0 == "" {
		t.Errorf("approved by %q, tree0 %q", got.ApprovedBy, got.Work.Tree0)
	}
	p, _, _ := f.d.Repo.CurrentProposal(context.Background(), a.ID)
	if !strings.Contains(p.Diff, "1.2.5") || len(p.Files) != 1 || p.Files[0] != "composer.lock" {
		t.Errorf("proposal = %v\n%s", p.Files, p.Diff)
	}
	if ev := f.audits("fix.apply"); len(ev) != 1 || ev[0].Actor != ActorAuto {
		t.Errorf("fix.apply audit = %+v", ev)
	}
	if sha := gitT(t, f.env, f.proj.Path, "rev-parse", "refs/heads/"+Branch(a.ID)); sha != p.CommitSHA {
		t.Errorf("branch = %s, want %s", sha, p.CommitSHA)
	}
	// Michel's update ran at Start, before the agent: the first message.
	msgs, _ := f.d.Repo.ListMessages(context.Background(), a.ID)
	if len(msgs) == 0 || msgs[0].Role != RoleMichel || !strings.Contains(msgs[0].Text, "composer update") {
		t.Errorf("first message = %+v", msgs)
	}
}

func TestAutoRefusesAgentEdits(t *testing.T) {
	f := newFixture(t)
	f.consent()
	level3(t, f)
	f.agentAct = func(ctx context.Context, d Deps, id, dir string) {
		writeFile(f.t, dir, "src/app.php", "<?php\n// adapted by the agent\n")
		if _, err := Propose(ctx, d, id, ProposeInput{Summary: "bump and adapt"}); err != nil {
			f.t.Errorf("Propose: %v", err)
		}
	}
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	if got := f.attempt(a.ID); got.State != StateProposed || got.ApprovedBy != "" {
		t.Errorf("an agent edit was applied alone: %+v", got)
	}
	if ref := gitT(t, f.env, f.proj.Path, "for-each-ref", "refs/heads/michel/"); ref != "" {
		t.Errorf("a branch was created: %s", ref)
	}
	if _, err := os.Stat(filepath.Join(f.attempt(a.ID).Work.Copy.Dir, "src", "app.php")); err != nil {
		t.Errorf("copy gone: %v", err)
	}
	if ev := f.audits("fix.auto"); len(ev) != 1 || ev[0].Result != "skipped" {
		t.Errorf("fix.auto audit = %+v", ev)
	}
}

func TestAutoRefusedWhenTestsRewriteLockfile(t *testing.T) {
	f := newFixture(t)
	f.consent()
	level3(t, f)
	proposeOnly(f)
	// The project's test command rewrites the lockfile where it runs: the
	// scratch worktree (ruling 37), never the snapshot. The proposal stays
	// Michel's own update and nothing of the test's write is committed.
	base := f.rec.onRun
	f.rec.onRun = func(name string, args []string, dir string) {
		base(name, args, dir)
		if name == "vendor/bin/phpunit" {
			writeFile(t, dir, "composer.lock", `{"packages":[{"name":"acme/lib","version":"1.2.5"},{"name":"evil/pkg","version":"1.0.0"}]}`+"\n")
		}
	}
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	got := f.attempt(a.ID)
	if got.State != StateApplied || got.ApprovedBy != ActorAuto {
		t.Errorf("Michel's own update was not applied: %+v", got)
	}
	p, _, _ := f.d.Repo.CurrentProposal(context.Background(), a.ID)
	if strings.Contains(string(p.DiffRaw), "evil/pkg") {
		t.Errorf("the test's write reached the proposal: %s", p.DiffRaw)
	}
	if b, _ := os.ReadFile(filepath.Join(f.proj.Path, "composer.lock")); strings.Contains(string(b), "evil") {
		t.Error("the test's write reached the project")
	}
}

func TestAutoReadsProposalCommitNotWorkingTree(t *testing.T) {
	f := newFixture(t)
	f.consent()
	level3(t, f)
	p := f.proj
	p.FixLevel = 1 // manual: the copy stays for the checks below
	f.update(p)
	proposeOnly(f)
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	got := f.attempt(a.ID)
	prop, _, _ := f.d.Repo.CurrentProposal(context.Background(), a.ID)
	wd := f.d.work()
	own, err := michelsOwnCommit(context.Background(), wd, got.Work.Copy, got.Work.Plan, prop.CommitSHA)
	if err != nil || !own {
		t.Fatalf("Michel's own commit: %v %v", own, err)
	}
	// The working tree turns hostile after the commit: the commit is what
	// is read.
	writeFile(t, got.Work.Copy.Dir, "composer.json", `{"name":"demo/app","require":{"acme/lib":"https://evil/x.zip"}}`+"\n")
	writeFile(t, got.Work.Copy.Dir, "composer.lock", `{"packages":[{"name":"acme/lib","version":"9.9.9","dist":{"type":"zip","url":"http://evil/x.zip"}}]}`+"\n")
	if own, err := michelsOwnCommit(context.Background(), wd, got.Work.Copy, got.Work.Plan, prop.CommitSHA); err != nil || !own {
		t.Errorf("the working tree was read instead of the commit: %v %v", own, err)
	}
	// And a commit holding the hostile files is refused whatever the
	// working tree says now.
	sha, err := workcopy.Commit(context.Background(), wd, got.Work.Copy, "hostile")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, got.Work.Copy.Dir, "composer.json", `{"name":"demo/app","require":{"acme/lib":"^1.0"}}`+"\n")
	writeFile(t, got.Work.Copy.Dir, "composer.lock", michelLock)
	if own, _ := michelsOwnCommit(context.Background(), wd, got.Work.Copy, got.Work.Plan, sha); own {
		t.Error("a hostile commit passed because the working tree is clean")
	}
}

func TestAutoRefusesURLConstraint(t *testing.T) {
	f := newFixture(t)
	f.consent()
	level3(t, f)
	f.agentAct = func(ctx context.Context, d Deps, id, dir string) {
		writeFile(f.t, dir, "composer.json", `{"name":"demo/app","require":{"acme/lib":"https://evil/x.zip"}}`+"\n")
		if _, err := Propose(ctx, d, id, ProposeInput{Summary: "bump"}); err != nil {
			f.t.Errorf("Propose: %v", err)
		}
	}
	a, err := Start(context.Background(), f.d, f.finding.ID, OriginAgent)
	if err != nil {
		t.Fatal(err)
	}
	f.wait(a.ID)
	if got := f.attempt(a.ID); got.State != StateProposed || got.ApprovedBy != "" {
		t.Errorf("a URL constraint was applied alone: %+v", got)
	}
	for cons, want := range map[string]bool{
		"^1.2.5": true, "~1.2": true, "1.2.5": true, ">=1.2": true, "v1.2.5": true,
		"https://evil/x.zip": false, "dev-master": false, "1.2.5 as 1.0.0": false, "npm:evil@1.0.0": false,
		"git+ssh://x/y": false, "file:../x": false, "@scope/pkg": false, "1.x": false, "*": false,
	} {
		m := `{"require":{"acme/lib":` + mustJSON(cons) + `}}`
		if got := manifestConstraintOK([]byte(m), "Packagist", "acme/lib"); got != want {
			t.Errorf("constraint %q: %v, want %v", cons, got, want)
		}
	}
	if manifestConstraintOK([]byte(`{"require":{"other/pkg":"^1.0"}}`), "Packagist", "acme/lib") {
		t.Error("a manifest without the package passed")
	}
	if !lockResolvesTarget([]byte(michelLock), "Packagist", "acme/lib", "1.2.5") {
		t.Error("Michel's lockfile refused")
	}
	for name, lock := range map[string]string{
		"other version": `{"packages":[{"name":"acme/lib","version":"1.2.4","dist":{"type":"zip","url":"https://x/y"}}]}`,
		"http dist":     `{"packages":[{"name":"acme/lib","version":"1.2.5","dist":{"type":"zip","url":"http://x/y"}}]}`,
		"no dist":       `{"packages":[{"name":"acme/lib","version":"1.2.5"}]}`,
		"absent":        `{"packages":[]}`,
	} {
		if lockResolvesTarget([]byte(lock), "Packagist", "acme/lib", "1.2.5") {
			t.Errorf("%s: accepted", name)
		}
	}
	npmLock := `{"lockfileVersion":3,"packages":{"":{},"node_modules/left-pad":{"version":"1.0.1","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.0.1.tgz"}}}`
	if !lockResolvesTarget([]byte(npmLock), "npm", "left-pad", "1.0.1") || lockResolvesTarget([]byte(npmLock), "npm", "left-pad", "1.0.2") {
		t.Error("npm lockfile check")
	}
	if !manifestConstraintOK([]byte(`{"dependencies":{"left-pad":"1.0.1"}}`), "npm", "left-pad") ||
		manifestConstraintOK([]byte(`{"dependencies":{"left-pad":"npm:evil@1.0.1"}}`), "npm", "left-pad") {
		t.Error("npm constraint check")
	}
}

func mustJSON(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}
